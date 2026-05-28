#!/usr/bin/env python3
"""Webwright sidecar server.

Long-lived process that accepts JSON-line commands on stdin and emits
JSON-line events on stdout. Keeps the Playwright browser warm between
tasks for faster startup and enables live progress streaming.

Protocol:
  Pick -> Sidecar (stdin):
    {"type": "start_task", "mode": "explore", "task": "...", "url": "...", "max_steps": 50}
    {"type": "execute_script", "script": "...", "url": "..."}
    {"type": "cancel"}

  Sidecar -> Pick (stdout):
    {"type": "step", "n": 1, "action": "navigating to ...", "screenshot": "<base64 or null>"}
    {"type": "finding", "severity": "high", "title": "...", "detail": "..."}
    {"type": "script_generated", "path": "..."}
    {"type": "complete", "summary": "...", "artifacts": {...}}
    {"type": "error", "message": "..."}
"""

import asyncio
import json
import sys
import os
import signal
from pathlib import Path

# Ensure output is line-buffered
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)


def emit(event: dict):
    """Send a JSON-line event to stdout."""
    print(json.dumps(event), flush=True)


def emit_step(n: int, action: str, screenshot: str | None = None):
    emit({"type": "step", "n": n, "action": action, "screenshot": screenshot})


def emit_error(message: str):
    emit({"type": "error", "message": message})


def emit_complete(summary: str, artifacts: dict):
    emit({"type": "complete", "summary": summary, "artifacts": artifacts})


async def run_explore_task(task: str, url: str, max_steps: int, output_dir: str, task_id: str):
    """Run a webwright explore task as a subprocess and stream events."""
    try:
        emit_step(0, f"initializing webwright for {url}")

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Build webwright CLI command
        endpoint = os.environ.get("OPENAI_BASE_URL", "http://127.0.0.1:9100/v1")
        endpoint_url = f"{endpoint}/chat/completions" if not endpoint.endswith("/chat/completions") else endpoint

        cmd = [
            "python3", "-m", "webwright.run.cli",
            "-c", "base.yaml",
            "-c", "model_openai.yaml",
            "-c", f"model.openai_endpoint={endpoint_url}",
            "-t", task,
            "--start-url", url,
            "--output-dir", output_dir,
            "--task-id", task_id,
        ]

        emit_step(1, f"starting exploration: {task}")

        # Run as subprocess (avoids nested event loop issues)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Watch output directory for new files while webwright runs
        step_n = 2
        seen_files = set()
        output_path = Path(output_dir)

        async def watch_files():
            """Poll output dir for new screenshots/steps and emit events."""
            nonlocal step_n
            while proc.returncode is None:
                await asyncio.sleep(2)
                if not output_path.exists():
                    continue
                for f in output_path.rglob("*"):
                    if f.is_file() and str(f) not in seen_files:
                        seen_files.add(str(f))
                        name = f.name
                        if name.endswith((".png", ".jpg", ".jpeg")):
                            # Read and base64 encode for live preview
                            import base64
                            try:
                                b64 = base64.b64encode(f.read_bytes()).decode()
                                emit({"type": "step", "n": step_n, "action": f"screenshot: {name}", "screenshot": b64})
                            except:
                                emit_step(step_n, f"screenshot: {name}")
                            step_n += 1
                        elif name.endswith(".sh"):
                            # Step scripts contain the action
                            try:
                                content = f.read_text()[:100].strip()
                                emit_step(step_n, f"executing: {content}")
                            except:
                                emit_step(step_n, f"step: {name}")
                            step_n += 1
                        elif name == "trajectory.json":
                            emit_step(step_n, "agent reasoning updated")
                            step_n += 1

        # Read stdout and watch files concurrently
        async def read_stdout():
            nonlocal step_n
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode().strip()
                if text:
                    emit_step(step_n, text[:200])
                    step_n += 1

        # Run both tasks — file watcher stops when proc finishes
        stdout_task = asyncio.create_task(read_stdout())
        watch_task = asyncio.create_task(watch_files())
        await proc.wait()
        watch_task.cancel()
        await stdout_task

        # Collect artifacts
        artifacts = {"screenshots": [], "scripts": [], "logs": []}
        for f in output_path.rglob("*.png"):
            artifacts["screenshots"].append(str(f.relative_to(output_path)))
        for f in output_path.rglob("*.py"):
            if f.name != "script.py":
                artifacts["scripts"].append(str(f.relative_to(output_path)))
        for f in output_path.rglob("*.json"):
            artifacts["logs"].append(str(f.relative_to(output_path)))

        if proc.returncode == 0:
            emit_complete(
                summary=f"Task complete. {len(artifacts['screenshots'])} screenshots, {len(artifacts['scripts'])} scripts.",
                artifacts=artifacts,
            )
        else:
            stderr = (await proc.stderr.read()).decode()[:500]
            emit_error(f"Webwright exited with code {proc.returncode}: {stderr}")

    except Exception as e:
        emit_error(str(e))


async def run_execute_task(script: str, url: str, output_dir: str):
    """Run a Python/Playwright script."""
    try:
        emit_step(0, "executing script")

        script_path = Path(output_dir) / "script.py"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(script)

        proc = await asyncio.create_subprocess_exec(
            "python3", str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            emit_complete(
                summary=f"Script executed successfully (exit code 0)",
                artifacts={"stdout": stdout.decode()},
            )
        else:
            emit_error(f"Script failed (exit code {proc.returncode}): {stderr.decode()[:1000]}")

    except Exception as e:
        emit_error(str(e))


async def main():
    """Main event loop: read commands from stdin, dispatch tasks."""
    emit({"type": "ready"})

    current_task = None

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            cmd = json.loads(line)
        except json.JSONDecodeError as e:
            emit_error(f"Invalid JSON: {e}")
            continue

        cmd_type = cmd.get("type", "")

        if cmd_type == "start_task":
            output_dir = cmd.get("output_dir", f"/tmp/webwright/{cmd.get('task_id', 'adhoc')}")
            task_id = cmd.get("task_id", "adhoc")

            if cmd.get("mode") == "explore":
                await run_explore_task(
                    task=cmd.get("task", ""),
                    url=cmd.get("url", ""),
                    max_steps=cmd.get("max_steps", 50),
                    output_dir=output_dir,
                    task_id=task_id,
                )
            elif cmd.get("mode") == "execute":
                await run_execute_task(
                    script=cmd.get("script", ""),
                    url=cmd.get("url", ""),
                    output_dir=output_dir,
                )
            else:
                emit_error(f"Unknown mode: {cmd.get('mode')}")

        elif cmd_type == "cancel":
            if current_task and not current_task.done():
                current_task.cancel()
                emit({"type": "cancelled"})

        elif cmd_type == "shutdown":
            emit({"type": "shutdown_ack"})
            break

        else:
            emit_error(f"Unknown command type: {cmd_type}")


if __name__ == "__main__":
    # Handle SIGTERM gracefully
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        pass
