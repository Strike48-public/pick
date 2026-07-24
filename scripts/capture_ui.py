#!/usr/bin/env python3
"""Capture screenshots and a GIF of a Pick connector UI feature for PRs.

Pick's UI is a Dioxus liveview app served by `pentest-web` on
http://localhost:3000/app. It boots to a "Connect to Strike48" gate; the
sidebar/Settings/Tools UI only renders after connecting. This script automates:

  1. launch `pentest-web` (unless one is already listening on :3000)
  2. open /app and submit the connect form against a local Strike48 studio
  3. navigate to a named view (a sidebar page)
  4. optionally run a short interaction (click a button, etc.)
  5. save PNG screenshots and record a WebM video, then convert it to a looping
     GIF with ffmpeg

Artifacts land in docs/assets/<feature>/ so they can be committed into the PR
diff and referenced from the PR body with a repo-relative path.

This is a developer tool, not a test. It has no assertions; it produces media.
It intentionally uses Playwright's Python API (already installed via mise) and
the system/bundled ffmpeg — no new MCP or Node toolchain required.

Usage (normally via scripts/capture-ui.sh):
  python3 scripts/capture_ui.py \
    --feature install-progress \
    --view Settings \
    --interaction install-first-tool \
    --host wss://studio.strike48.test \
    --tenant <uuid>

Environment fallbacks for --host / --tenant: STRIKE48_HOST / STRIKE48_TENANT.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit(
        "playwright is not importable. Install it in the mise python env:\n"
        "  pip install playwright && playwright install chromium"
    )

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_BIN = REPO_ROOT / "target" / "debug" / "pentest-web"
APP_URL = "http://localhost:3000/app"
PORT = 3000


def log(msg: str) -> None:
    print(f"[capture-ui] {msg}", flush=True)


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ensure_web_server(host: str, tenant: str) -> "subprocess.Popen | None":
    """Launch pentest-web if nothing is already serving on :3000.

    Returns the spawned process (so the caller can terminate it) or None if an
    existing server was reused.
    """
    if port_open(PORT):
        log(f"reusing existing server on :{PORT}")
        return None
    if not WEB_BIN.exists():
        sys.exit(
            f"web binary not found at {WEB_BIN}.\n"
            "Build it first: cargo build --package pentest-web"
        )
    log("launching pentest-web ...")
    env = {**os.environ, "STRIKE48_HOST": host, "STRIKE48_TENANT": tenant, "RUST_LOG": "warn"}
    proc = subprocess.Popen(
        [str(WEB_BIN)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        if port_open(PORT):
            log("server is up")
            return proc
        time.sleep(0.5)
    proc.terminate()
    sys.exit("pentest-web did not start listening on :3000 within 20s")


def to_gif(webm: Path, gif: Path, fps: int, width: int) -> bool:
    """Convert a WebM recording to a looping GIF via ffmpeg (two-pass palette)."""
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        log("ffmpeg not found on PATH; skipping GIF conversion")
        return False
    palette = gif.with_suffix(".palette.png")
    vf = f"fps={fps},scale={width}:-1:flags=lanczos"
    try:
        subprocess.run(
            [ffmpeg, "-y", "-i", str(webm), "-vf", f"{vf},palettegen", str(palette)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [ffmpeg, "-y", "-i", str(webm), "-i", str(palette),
             "-lavfi", f"{vf} [x]; [x][1:v] paletteuse", "-loop", "0", str(gif)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        log(f"ffmpeg failed: {e}; leaving WebM only")
        return False
    finally:
        palette.unlink(missing_ok=True)
    return True


# --- Interactions -----------------------------------------------------------
# Each interaction is a small function (page, out_dir) -> None that drives a
# specific feature and drops screenshots. Add new ones here as features land.

def interaction_install_first_tool(page, out_dir: Path) -> None:
    """Click the first per-tool Install button and capture the progress bar."""
    page.wait_for_selector("h2:has-text('Tools')", timeout=15000)
    page.locator("h2:has-text('Tools')").scroll_into_view_if_needed()
    page.wait_for_timeout(4000)  # let the catalog probe install state
    page.screenshot(path=str(out_dir / "01-tools-catalog.png"), full_page=True)

    btns = page.locator("button:has-text('Install')")
    for i in range(btns.count()):
        b = btns.nth(i)
        try:
            if b.inner_text().strip() == "Install" and b.is_enabled():
                b.scroll_into_view_if_needed()
                b.click()
                break
        except Exception:
            continue
    # Capture a couple of early frames where the elapsed clock is ticking.
    page.wait_for_timeout(700)
    page.screenshot(path=str(out_dir / "02-installing.png"), full_page=True)


INTERACTIONS = {
    "install-first-tool": interaction_install_first_tool,
}


def connect(page, host: str, tenant: str) -> None:
    page.goto(APP_URL, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_selector("button:has-text('Connect')", timeout=20000)
    page.fill("input >> nth=0", host)
    page.fill("input >> nth=1", tenant)
    page.click("button:has-text('Connect')")
    page.wait_for_selector("text=Settings", timeout=45000)
    log("connected to studio")


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture Pick UI media for PRs.")
    ap.add_argument("--feature", required=True,
                    help="slug for the output dir (docs/assets/<feature>/)")
    ap.add_argument("--view", default="Settings",
                    help="sidebar page to open (label text, e.g. Settings, Tools)")
    ap.add_argument("--interaction", choices=sorted(INTERACTIONS), default=None,
                    help="named interaction to run and record")
    ap.add_argument("--host", default=os.environ.get("STRIKE48_HOST", ""),
                    help="Strike48 host (or set STRIKE48_HOST)")
    ap.add_argument("--tenant", default=os.environ.get("STRIKE48_TENANT", ""),
                    help="Strike48 tenant id (or set STRIKE48_TENANT)")
    ap.add_argument("--fps", type=int, default=8, help="GIF frame rate")
    ap.add_argument("--width", type=int, default=900, help="GIF width in px")
    ap.add_argument("--no-video", action="store_true",
                    help="screenshots only; skip video/GIF recording")
    args = ap.parse_args()

    if not args.host or not args.tenant:
        sys.exit("--host and --tenant are required (or set STRIKE48_HOST/STRIKE48_TENANT)")

    out_dir = REPO_ROOT / "docs" / "assets" / args.feature
    out_dir.mkdir(parents=True, exist_ok=True)
    log(f"artifacts -> {out_dir.relative_to(REPO_ROOT)}")

    server = ensure_web_server(args.host, args.tenant)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx_kwargs = {"viewport": {"width": 1400, "height": 1000}}
            if not args.no_video:
                ctx_kwargs["record_video_dir"] = str(out_dir)
                ctx_kwargs["record_video_size"] = {"width": 1400, "height": 1000}
            context = browser.new_context(**ctx_kwargs)
            page = context.new_page()
            page.on("pageerror", lambda e: log(f"pageerror: {e}"))

            connect(page, args.host, args.tenant)

            # Navigate to the requested sidebar view.
            page.click(f".sidebar-flat-label:has-text('{args.view}')", timeout=10000)
            page.wait_for_timeout(1500)
            page.screenshot(path=str(out_dir / "00-view.png"), full_page=True)
            log(f"captured view: {args.view}")

            if args.interaction:
                INTERACTIONS[args.interaction](page, out_dir)
                log(f"ran interaction: {args.interaction}")

            # Finalize video: closing the context flushes the .webm file.
            context.close()
            browser.close()

        if not args.no_video:
            webms = sorted(out_dir.glob("*.webm"))
            if webms:
                webm = webms[-1]
                gif = out_dir / f"{args.feature}.gif"
                if to_gif(webm, gif, args.fps, args.width):
                    log(f"wrote {gif.relative_to(REPO_ROOT)}")
                    webm.unlink(missing_ok=True)  # keep only the GIF
                else:
                    log(f"kept video: {webm.relative_to(REPO_ROOT)}")
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
            log("stopped pentest-web")

    log("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
