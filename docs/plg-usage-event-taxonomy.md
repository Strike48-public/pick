# PLG Usage-Event Taxonomy, Privacy Model & Who/How Dashboard

Status: Draft for security sign-off
Issue: [project-management#101](https://github.com/Strike48/project-management/issues/101)
Parent epic: [project-management#72](https://github.com/Strike48/project-management/issues/72) (`init/plg`)
Applies to: [`Strike48-public/pick`](https://github.com/Strike48-public/pick), [`Strike48-public/strikehub`](https://github.com/Strike48-public/strikehub)
Canonical home: this file (`docs/plg-usage-event-taxonomy.md` in `pick`, the primary telemetry consumer). StrikeHub links here rather than forking a copy.

## Purpose

This is the single shared contract that both Pick and StrikeHub code against so usage
analytics are consistent, comparable across apps, and privacy-safe. It answers the PLG
throughline: **who is using the apps, and how**, without ever shipping PII, target data, or
scan results off the device.

It is a spec, not code. It defines the event names, the properties allowed on each, the
identity model, the consent behavior, the Sentry project layout, and the dashboard both apps
feed. Implementations that emit telemetry MUST conform to it. Where the current code diverges,
this document says so and the code is the thing that changes.

## Grounding: what exists today

This spec is reverse-engineered from and reconciles the two live implementations, so it is a
contract they can actually meet, not an idealized invention.

| Surface | File | Event mechanism today | Identity today |
|---|---|---|---|
| Pick | `crates/core/src/telemetry.rs` (PR #249, unmerged) | `Activity` enum -> `scan.start` / `tool.run` / `network.check`, single `record()` choke point; names marked PROVISIONAL pending this spec | Pseudonymous `device_id`; `send_default_pii = false` |
| StrikeHub | `crates/sh-core/src/sentry_init.rs` (merged) | `traces_sampler` spans: `oauth.flow` / `connector.start` / `connector.fetch` / `bridge.request`; nav events e.g. `nav.connector.kubestudio` | `set_user_context(...)` called from `sh-ui/src/app.rs` with `user_id = None`, `email = auth.user_email()`, `username = auth.user_display_name()` -- **email + display name are the Sentry identity**; `before_send` scrubs headers/`token` only, not `event.user` |

Two divergences between the apps force decisions this spec must make (see
[Reconciliation](#reconciliation-required-code-changes)):

1. **StrikeHub transmits `email`** in its user context. Pick is strictly pseudonymous. The
   issue's explicit "no PII" rule cannot hold for both simultaneously.
2. **`app.mode` means different things**: Pick uses it for form-factor (`mobile`/`desktop`);
   StrikeHub uses it for process role (`desktop`/`server`). A shared tag with two meanings is
   not shared.

## Design principles

1. **Anonymous by default, pseudonymous at most.** Nothing that leaves the device identifies a
   natural person. The strongest identifier we transmit is an opaque per-install id and, once
   authenticated, an opaque tenant/user id, never an email, name, or handle.
2. **No target data, ever.** Hostnames, IPs, CIDRs, ports, tool arguments, scan output, report
   contents, and command lines never leave the device. This is the hard line the connector's
   `pii-check.yml` already enforces on source; telemetry extends it to runtime.
3. **Coarse over precise.** Event properties are enums, booleans, and bounded counts. When in
   doubt, bucket it (`1`, `2-5`, `6-20`, `20+`) rather than send an exact number that could
   fingerprint an environment.
4. **One choke point per app.** Every event routes through a single module
   (Pick: `telemetry::record`; StrikeHub: equivalent) so the safe-value rule is auditable in
   one place and renames are a one-file change.
5. **Opt-out, honored everywhere.** Telemetry is on by default (PLG needs the signal) but a
   single setting and a single env override disable it completely, before any client init.
6. **Fail closed on privacy.** Absent DSN, opt-out, or any doubt about a value's safety: send
   nothing. A missing event is always preferable to a leaked one.

## Naming convention

All event and span names are lowercase `domain.action`, dot-separated, `snake_case` within a
segment. Tags are lowercase `namespace.key`. This unifies Pick's `scan.start` style with
StrikeHub's `oauth.flow` style; both already conform, so no renames are required for existing
names, only additions.

- Good: `scan.start`, `tool.run`, `connector.register`, `update.applied`
- Bad: `ScanStarted`, `scanStart`, `scan-start`, `run_tool`

## Event taxonomy

Events are grouped by lifecycle. Each event lists its allowed properties. **Any property not
listed is forbidden.** Property values are the safe types noted; free-form strings are only
permitted where explicitly marked "enum" with the enum values enumerated here.

### Session / lifecycle (release health)

Handled by Sentry release-health sessions (`auto_session_tracking: true`), not custom events.
This yields DAU/WAU, crash-free rate, and adoption-per-release for free. No custom event is
emitted for app start/stop; the session is the event.

| Concept | Source |
|---|---|
| `session` (start/end, crash-free) | Sentry automatic release-health |
| `install` (first-run) | Derived from first appearance of a `device_id`; no explicit event |

### Activation & core value

| Event | When | Allowed properties |
|---|---|---|
| `network.check` | A network discovery/check completes (the core "did they get value" signal) | `result` (enum: `ok`, `empty`, `error`), `host_count_bucket` (enum: `0`, `1`, `2-5`, `6-20`, `21-100`, `100+`) |
| `scan.start` | Easy-mode "Scan My Network" action fired | `channel` (enum: `easy`, `advanced`) |
| `tool.run` | A connector tool executed | `tool` (enum: the registered tool name, e.g. `nmap`, `masscan`; **name only, never arguments**), `outcome` (enum: `ok`, `error`, `timeout`) |

`host_count_bucket` is bucketed deliberately: an exact host count on a small network is
environment-fingerprinting. Buckets give the funnel its shape without the precision.

### Easy-mode UX (Pick)

| Event | When | Allowed properties |
|---|---|---|
| `easy.scan_tap` | The one-tap scan button pressed | none |
| `easy.doc_view` | In-app report/doc viewer opened | none |
| `easy.history_open` | Conversation history opened | none |

### Connector / PLG (both apps)

| Event | When | Allowed properties |
|---|---|---|
| `connector.register` | Connector registration attempted | `mode` (enum: `plg_approved`, `tokenless_pending`, `manual`), `outcome` (enum: `ok`, `error`) |
| `oauth.flow` | OAuth sign-in flow ran | `outcome` (enum: `ok`, `error`, `cancelled`, `timeout`) |
| `connector.start` | Connector process started | `outcome` (enum: `ok`, `error`) |

### Share (Pick #284)

| Event | When | Allowed properties |
|---|---|---|
| `share.open` | Native share sheet / social intent opened | `channel` (enum: `x`, `linkedin`, `facebook`, `os_sheet`, `copy_link`), `subject` (enum: `report`, `usage_summary`) |

`share.open` records **intent to share** (sheet opened), not confirmed shares; the OS does not
report back completion, and we do not attempt to. No shared content, URL, or report body is
ever a property.

### Distribution / update (Pick #282, StrikeHub #55)

| Event | When | Allowed properties |
|---|---|---|
| `update.available` | Update detected | `channel` (enum: `auto`, `manual`) |
| `update.applied` | Update installed | `outcome` (enum: `ok`, `error`) |

## Common tags (on every event and session)

Set once at scope configuration; attached to everything. This is where the app-comparison
dimensions live.

| Tag | Values | Notes |
|---|---|---|
| `app.name` | `pick`, `strikehub` | **New, required.** Distinguishes the two apps in a shared org. Neither app sets this today; both MUST add it. |
| `app.platform` | `linux`, `macos`, `windows`, `android`, `ios`, `unknown` | From `std::env::consts::OS`. Both apps set this. |
| `app.arch` | `x86_64`, `aarch64`, ... | Both apps set this. |
| `app.form_factor` | `mobile`, `desktop`, `server` | **Renamed from `app.mode`** to resolve the clash. `mobile`/`desktop` for Pick, `desktop`/`server` for StrikeHub. |
| `app.channel` | `easy`, `advanced` | Easy-mode vs full UI. Pick sets this; StrikeHub sets `advanced` (no easy mode yet). |
| `release` | semver | Sentry release; drives adoption-per-release. Both set this. |
| `environment` | `development`, `production` | From build profile. Never report `development` builds to the prod project (see [Sentry layout](#sentry-project-layout)). |

Authenticated (PLG) tags, set only after sign-in, still pseudonymous:

| Tag | Values | Notes |
|---|---|---|
| `plg.tenant` | opaque tenant id | Pick sets this via `set_plg_identity`. Opaque slug/uuid, never a customer name. |

## Identity & privacy model

### The identity ladder (each rung is pseudonymous)

1. **Anonymous install id (`device_id`)** -- a random UUID generated on first run, persisted
   locally, sent as the Sentry `user.id`. It is per-install, not per-person; a reinstall is a
   new "user". This is the default and the floor.
2. **Authenticated PLG identity** -- after OAuth sign-in, attach an **opaque tenant/user id**
   as `plg.tenant` (and optionally `user.id` set to an opaque subject id). This lets us see
   activation-through-signup without knowing who the person is.

There is no third rung. We never attach email, name, username, avatar, or IP.

### The hard "no PII / no target data" rule

The following MUST NOT appear in any event, property, tag, breadcrumb, span, or Sentry user
field, on any code path:

- Email addresses, real names, usernames, handles, avatars.
- IP addresses (Sentry `send_default_pii` MUST be `false`; the server IP the app connects to
  MUST NOT be attached).
- Target hostnames, IPs, CIDRs, ports, MAC addresses.
- Tool arguments, command lines, flags, or any `execute_command`-style payload.
- Scan output, findings, report contents, document bodies, share text.
- Customer or tenant **names** (opaque ids only; names are PII per the Pick CLAUDE.md
  Customer Data rule).
- Auth material: tokens, JWTs, OTTs, session cookies, `Authorization` headers.

This mirrors and extends the connector's `pii-check.yml`, which enforces the same classes on
source at CI time. Telemetry is the runtime extension of that gate.

### Defense in depth: `before_send` scrubber (both apps, required)

StrikeHub already implements a `before_send` hook that drops `Authorization` headers and any
key containing `token`. This spec makes that scrubber **mandatory for both apps** and widens
it to a shared denylist: any event whose keys or string values match the forbidden classes
above is dropped or redacted before transmit. Pick does not have this hook yet and MUST add
it. The choke point (`record`) is the first line; `before_send` is the backstop for anything
that routes around it (panics, tracing integration, third-party crumbs).

## Consent & opt-out behavior

- **Default:** enabled. PLG analytics need the signal, and the data is anonymous by
  construction, so opt-out (not opt-in) is the posture. This is a product decision that this
  spec records for security sign-off, not a foregone conclusion.
- **Setting:** `telemetry_enabled: bool` (Pick has this, default `true`). StrikeHub MUST expose
  an equivalent.
- **Env override:** `STRIKE48_TELEMETRY=0|false|off|no` disables telemetry regardless of the
  setting, before client init. Lets any operator or CI kill it without touching UI. Pick has
  this; StrikeHub MUST add it.
- **Where surfaced:** a plain-language line in Settings ("Anonymous usage analytics -- helps
  us see which features get used. No scan data, targets, or personal info is ever sent.") with
  a toggle, plus a one-line mention in the first-run/easy-mode flow linking to the privacy
  note. The toggle takes effect on next launch (client init is once-per-process); the UI MUST
  say so.
- **Build-time kill switch:** absent `SENTRY_DSN` at compile time, telemetry is a hard no-op.
  Forks and local/dev builds send nothing by construction. Only release CI injects the DSN.

## Sentry project layout

- **Two projects per environment, not one shared bucket:** `pick` and `strikehub`, each with a
  `production` and `development` environment. Rationale: independent quotas and alerting,
  clean per-app crash-free rates, and no risk of one app's volume starving the other's
  release-health data. The `app.name` tag additionally allows a cross-app combined view via a
  Sentry dashboard spanning both projects.
- **Development builds never report to production.** The `environment` tag gates this, and the
  DSN-at-build-time model means dev builds usually have no DSN at all.
- **Retention & sampling:** release-health sessions at 100% (cheap, and DAU/WAU needs them).
  Activity events at 100% initially (volume is low in PLG early days); revisit sampling only
  if quota pressure appears. Tracing spans (StrikeHub's `oauth.flow` etc.) keep their existing
  sampler; do not raise trace sampling for business analytics -- use events, which are
  cheaper, for the funnel.

### Cost note (implementation guidance, not blocking)

Pick's current `record()` emits **both** a breadcrumb and a `capture_message` per activity.
`capture_message` is a full event and counts against quota. For high-frequency `tool.run` this
could be noisy and costly. Recommendation: keep `capture_message` for the low-frequency funnel
milestones (`scan.start`, `network.check`) and consider demoting very frequent events to
breadcrumbs-plus-metric, or sample them, once real volume is observed. Flagged here so the
dashboard owner and the Pick implementer decide together; not a blocker for the spec.

## The "who / how" dashboard

One Sentry dashboard (spanning both projects, filtered by `app.name`) with these panels. Each
panel names the query dimension so it is buildable directly.

### Who

1. **DAU / WAU / MAU** -- release-health sessions, unique `user.id`, split by `app.name`.
2. **New vs returning** -- first-seen vs repeat `device_id` over the window.
3. **Platform breakdown** -- sessions grouped by `app.platform` + `app.arch`.
4. **Channel breakdown** -- sessions grouped by `app.channel` (easy vs advanced) and
   `app.form_factor` (mobile/desktop/server).
5. **Release adoption** -- sessions grouped by `release`; shows upgrade uptake (feeds #282/#55).
6. **Authenticated ratio** -- share of sessions with a `plg.tenant` tag set (signup conversion
   proxy).

### How

7. **Activation funnel** -- `session` -> `scan.start` -> `network.check{result=ok}`. The core
   "did a new user get value" funnel.
8. **Per-activity volume** -- counts of `network.check`, `tool.run`, `scan.start` over time.
9. **Tool popularity** -- `tool.run` grouped by `tool` enum. Which tools actually get used.
10. **Outcome health** -- `network.check` / `tool.run` grouped by `result`/`outcome`; surfaces
    silent failure and error spikes.
11. **Share funnel** -- `share.open` grouped by `channel` and `subject` (feeds #284, #106).
12. **Update funnel** -- `update.available` -> `update.applied{outcome=ok}` (feeds #282, #55).

### Crash-free (health, always on)

13. **Crash-free sessions/users per release** -- standard Sentry release-health, split by
    `app.name`.

## Reconciliation: required code changes

This spec resolves the two divergences by making the code change, not by weakening the rule.
These are the deltas each app owner must land to conform; each is small and localized.

### StrikeHub

1. **Stop sending email + display name.** `sh-ui/src/app.rs` calls `set_user_context` with
   `user_id = None` and the user's **email** as the Sentry `user.email` (plus display name as
   `user.username`), and `before_send` does not scrub `event.user`. Per the no-PII rule, pass
   an opaque subject id as `user.id` and drop `email`/`username` entirely.
   **This is the one confirmed active PII leak and should be treated as SHOULD-FIX-before-PLG,**
   because an email + real name are leaving StrikeHub installs on every authenticated session
   today.
2. **Rename `app.mode` -> `app.form_factor`** with values `desktop`/`server`.
3. **Add `app.name = "strikehub"`** to the scope.
4. **Add the opt-out setting + `STRIKE48_TELEMETRY` env override** (Pick already has both).
5. Adopt the shared event names for `connector.register` / `update.*` when #54 and #55 land.

### Pick

1. **Rename `app.mode` -> `app.form_factor`** with values `mobile`/`desktop`.
2. **Add `app.name = "pick"`** to the scope.
3. **Add a `before_send` scrubber** matching StrikeHub's (shared denylist backstop).
4. Replace the provisional `Activity` enum's names/properties with the taxonomy above
   (`network.check` gains `result` + `host_count_bucket`; `tool.run` gains `tool` + `outcome`;
   add `scan.start.channel`). Because names route through one choke point, this is a one-file
   change, exactly as the module's own docs anticipate.
5. Reconsider `capture_message`-per-activity for high-frequency events (see cost note).

## Security sign-off checklist

For the security reviewer. Sign-off gates the analytics parts of #278, #54, and #284.

- [ ] The forbidden-data list is complete and matches `pii-check.yml`'s classes.
- [ ] `send_default_pii = false` verified in both apps (no IPs).
- [ ] StrikeHub `email`/`username` transmission removed (change #1 above landed).
- [ ] `before_send` scrubber present and covering the shared denylist in both apps.
- [ ] Opt-out default posture (on-by-default, anonymous) accepted, or changed to opt-in here.
- [ ] Consent copy in Settings + first-run reviewed for accuracy ("no scan data / targets /
      PII").
- [ ] Confirm no target data, tool args, or report contents reachable via any property, tag,
      breadcrumb, span, or user field on any code path.
- [ ] DSN handling: build-time only, absent in forks/dev, not committed to source.

## Open questions for sign-off

1. **Opt-out vs opt-in.** This spec assumes opt-out (on by default) because the data is
   anonymous by construction and PLG needs the signal. Security/legal may require opt-in in
   some jurisdictions. Decision needed; the code supports either by flipping
   `default_telemetry_enabled`.
2. **`user.id` for authenticated sessions.** Do we set Sentry `user.id` to the opaque tenant
   subject id once signed in, or keep the anonymous `device_id` and only add `plg.tenant`?
   The former ties multi-device usage to one identity (better funnel) but is a stronger
   pseudonymous identifier. Recommend `plg.tenant` tag only, `user.id` stays the install id.
3. **StrikeHub email removal urgency.** Is the current email transmission a compliance issue
   that needs a hotfix ahead of the rest of this work, or is it acceptable until the PLG
   telemetry pass? Flagging for the reviewer to rank.
