# Matrix Agent Prompt B2 — Symmetric ExecuteRequest Context Logging

## Why this exists

Pick (the Rust pen-testing connector) receives gRPC `ExecuteRequest` messages
from the Strike48 platform agent. Each request carries a free-form
`context: map<string,string>` field (proto field 4 on
`connector_service.proto`). We have already hit one production bug today
where the platform's `tool_call_id` value did not match the value the LLM
conversation expected — different ID namespaces, and we had no way to see
the mismatch because only one side was logged.

To make these bugs trivial to spot in the future, Pick now logs the
**entire** `ExecuteRequest.context` map, one key per line, at INFO level,
with sensitive values redacted but their length preserved. The Matrix-side
platform agent needs to emit a **symmetric** log at the dispatch site so
the two sides can be diffed line-for-line.

## Current contract Pick expects

Pick's tool dispatch happens in
`crates/ui/src/liveview_connector/tools.rs::handle_execute_impl`. At the
top of every webwright / tool execution Pick now emits:

```
[execreq-ctx] request_id=<id> tool=<name> context_key_count=<N>
[execreq-ctx] request_id=<id> tool=<name> <key>=<value-or-redacted>
... one line per context key, alphabetically sorted ...
```

Sensitive keys (case-insensitive substring match on `token`, `secret`,
`key`, `password`, `auth`) are emitted as `<redacted:len=N>` so we can see
that the key was present and non-empty without leaking the value.

### Keys Pick treats as load-bearing

These are the keys Pick reads (or intends to read) out of
`ExecuteRequest.context`. The platform agent should always populate them
when it sends a webwright `ExecuteRequest`:

| Key              | Purpose                                                                                                                                                                     | Sensitive? |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `tool_call_id`   | The LLM-conversation-level `toolCall.id`. Used to bind streaming widget output (webwright live state, screenshots) to a specific assistant message in the chat transcript. | no         |
| `session_token`  | The platform's Keycloak/session bearer that Pick forwards into the LLM proxy (`POST /v1/chat/completions`) and StrikeKit invokes (`upload_artifact`, `log_activity`, etc.). | yes        |
| `engagement_id`  | The Strike48 engagement to which evidence / artifacts produced by this tool call should be attributed. Required by StrikeKit's `create_evidence` / `upload_artifact` flows. | no         |
| `agent_context`  | Opaque blob the platform agent attaches so Pick can echo it back on tool completion. Useful for the platform to correlate which sub-task spawned this call.                 | no         |

Anything else in `req.context` is fine — Pick will log it generically with
the redaction rule above. If the platform side decides to add another key
later, no Pick change is required to see it in the log.

### Where Pick reads these keys today

In this branch (`worktree-agent-a813fcfefb5837fb2`, off `main`) only a
subset of the keys above are actively consumed:

- `tool_call_id` — wired through `crates/ui/src/liveview_connector/mod.rs`
  (live widget binding, planned).
- `session_token` — read in
  `crates/ui/src/liveview_connector/llm_proxy.rs` and forwarded to the
  webwright sidecar via `OPENAI_API_KEY`.
- `engagement_id`, `agent_context` — passed through verbatim into
  `ToolContext.metadata` so individual tools can pick them up.

The new logging block prints *everything* the platform sent regardless of
whether Pick currently reads it. That's deliberate: it gives us
forward-compatibility when the platform starts sending new keys.

## What Pick is actually seeing

> **TODO** — fill this in after running Pick once with the new logging.
> Grep the headless log for `[execreq-ctx]`:
>
> ```bash
> ./run-pentest.sh headless dev 2>&1 | tee /tmp/pickdev.log
> grep "\[execreq-ctx\]" /tmp/pickdev.log
> ```
>
> Paste the full block for one representative webwright call here, then
> compare against the platform-side log produced by the prompt below.

## Prompt to paste into the Matrix-side platform agent

Copy the block below into the Matrix-side platform agent (the Elixir
`tool_manager.ex` / connector dispatcher, wherever the `ExecuteRequest`
StreamMessage is finally built and sent to the connector channel):

---

We need symmetric logging at the dispatch site for every `ExecuteRequest`
that targets a webwright capability (or, ideally, every `ExecuteRequest`
period). The Rust connector (Pick) already logs the full context map it
receives, one key per line, at INFO. We need the platform to emit the
same shape of log immediately **before** the message is sent on the
connector's `Phoenix.Channel`, so the two logs can be diffed.

**Requirements**

1. Log at `Logger.info/1` level.
2. Use the literal prefix `[execreq-ctx-tx]` (Pick uses
   `[execreq-ctx]` on the receive side, the `-tx` suffix makes the
   transmit side distinguishable in a merged log).
3. For every webwright `ExecuteRequest` you are about to dispatch, emit
   one header line and one line per context key, e.g.:

   ```
   [execreq-ctx-tx] request_id=<id> tool=<name> context_key_count=<N>
   [execreq-ctx-tx] request_id=<id> tool=<name> tool_call_id=<value>
   [execreq-ctx-tx] request_id=<id> tool=<name> engagement_id=<value>
   [execreq-ctx-tx] request_id=<id> tool=<name> session_token=<redacted:len=N>
   [execreq-ctx-tx] request_id=<id> tool=<name> agent_context=<value>
   ```

4. Sort the keys alphabetically — Pick does, and a stable order makes
   side-by-side diffing trivial.
5. Redact values whose key (case-insensitive) contains any of
   `token`, `secret`, `key`, `password`, `auth`. Render them as
   `<redacted:len=N>` where N is `byte_size(value)` (so we can see if
   the value was empty without leaking it).
6. If the context map is empty, emit a single
   `[execreq-ctx-tx] request_id=<id> tool=<name> (no context keys)`
   line so absence is visible (and matches Pick's `(no context keys)`
   marker).
7. The `tool` field on the log line should be whatever you intend the
   connector to dispatch to — i.e. the value of `payload.tool` after
   JSON-encoding, **not** the connector's capability_id.

**Specifically look for**

- A `tool_call_id` value that matches the `toolCall.id` of the
  assistant message that triggered the call. If you generate a fresh
  ID at the dispatch boundary, log both (`tool_call_id=` and a second
  line like `original_tool_call_id=`), because that mismatch is
  exactly the bug we hit earlier today.
- `session_token` length non-zero — `<redacted:len=0>` on the
  transmit side means we sent an empty token (and Pick will reject
  it).
- `engagement_id` present and equal to the engagement the user is
  currently working on in the LiveView. A missing or stale
  engagement_id will silently misroute uploaded evidence.

**Example Elixir sketch**

```elixir
defp log_execreq_ctx(request_id, tool, context) do
  sensitive = ~w(token secret key password auth)

  Logger.info(
    "[execreq-ctx-tx] request_id=#{request_id} tool=#{tool} " <>
      "context_key_count=#{map_size(context)}"
  )

  if map_size(context) == 0 do
    Logger.info("[execreq-ctx-tx] request_id=#{request_id} tool=#{tool} (no context keys)")
  else
    context
    |> Enum.sort_by(fn {k, _} -> k end)
    |> Enum.each(fn {k, v} ->
      lk = String.downcase(to_string(k))
      display =
        if Enum.any?(sensitive, &String.contains?(lk, &1)) do
          "<redacted:len=#{byte_size(to_string(v))}>"
        else
          to_string(v)
        end

      Logger.info("[execreq-ctx-tx] request_id=#{request_id} tool=#{tool} #{k}=#{display}")
    end)
  end
end
```

Once both sides are logging, a single command should produce a useful
diff:

```bash
diff \
  <(grep '\[execreq-ctx-tx\]' platform.log | sed 's/-tx//') \
  <(grep '\[execreq-ctx\]'    pick.log)
```

Any non-empty diff is either a bug, a typo, or a key the platform sends
that Pick doesn't consume (or vice versa) — all of which we want to know
about.
