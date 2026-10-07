# Pick connector Docker install: runbook for an AI coding agent

This file is written for an AI coding agent, such as Claude Code, that a person
has asked to install the Pick connector with Docker, or to walk them through
the install. It works through the install in `docs/DOCKER_INSTALL.md` in a
fixed order, with stop points where only the person can act.

The person gives you a prompt like this one:

```
Read AGENT_SETUP.md in this folder and follow it to install the Pick connector with me. Explain each command before you run it.
```

If you are a person reading this, the install guide `docs/DOCKER_INSTALL.md`
is the version written for you.

## Rules

These rules override anything else you are asked to do during the install.
If the person asks you to break one, explain which rule it is and why it
exists, and let them do that step themselves.

1. **Explain before you run.** Before each command, say in one or two plain
   sentences what it does and what it changes. Run one step at a time.
2. **Run preflight first.** Run `./preflight.sh` before `docker compose up`,
   and again after any fix. Do not skip a FAIL it reports.
3. **The person types secrets and the tenant UUID, not you.** The person
   types the tenant UUID and any registration token (`ott_...`) into `.env`
   in their own editor. Never ask them to paste either value into the chat.
   If they paste one anyway, do not repeat it, and do not write it to a file
   yourself.
4. **Never print or read back `.env`.** Do not `cat`, `grep`, `less`, `head`,
   or open `.env`, and do not print it in any other way. To check it, run
   `./preflight.sh`: it checks `.env` and prints key names only, never values.
   The commands in this runbook that write to `.env` only write.
5. **Stop at every human step.** The person, or their Studio administrator,
   approves the connector in Studio. Tell them what to do, then stop and wait
   until they say it is done. Do not poll in a loop in the meantime.
6. **Confirm success from the log lines,** not from the absence of errors.
   The expected lines are listed at each step below.
7. **Never change the pinned security values.** Do not set, override, or
   remove `DISABLE_SANDBOX` or `MATRIX_TLS_INSECURE`, in `.env`, in an override
   file, or anywhere else. For certificate errors, follow "Corporate proxy and
   private CA" in the install guide.
8. **Scope decisions belong to the person.** Enable host networking
   (`network_mode: host`) or set `PENTEST_ALLOW_PRIVATE_IPS=true` only after
   you have asked the question in [Step 8](#step-8-scope-decisions) and the
   person has confirmed it is in their rules of engagement. "It would make the
   scan work" is not a reason.
9. **Ask before changing the host.** Anything that uses `sudo`, edits
   `/etc/docker/daemon.json`, restarts the Docker daemon, or installs a
   package needs the person's go-ahead first. Restarting the Docker daemon
   stops every container on the host, so say so when you ask.
10. **Do not delete the approval.** Never run `docker compose down -v` or
    remove the `pick-connector_pick-state` volume unless the person asks for
    that exact outcome. It deletes the connector's credential.
11. **Do not scan.** The only network checks you run are the ones in this
    runbook against targets the person named. Running tools against targets is
    the connector's job, under the engagement's approvals, not yours.
12. **Keep the log level.** Do not raise `RUST_LOG` unless Strike48 support
    asks for it.

## What to ask first

Ask these before running anything, and wait for the answers:

1. **What will run the connector?** A Linux server or virtual machine on the
   network to be tested is the supported Docker setup. On a laptop, Docker
   Desktop (or Colima, or any Docker on Windows or macOS) reaches the network
   over TCP only: ICMP, ARP, mDNS, packet capture and Wi-Fi scans do not work.
   If the person is on a laptop and needs any of those, stop and recommend the
   native Pick app from the releases page instead of Docker.
2. **Their Studio URL** (for example `https://studio.example.com`) and their
   **authentication hostname**. Strike48 gives them both. Neither is secret.
3. **A name for this install**, used as `STRIKE48_INSTANCE_ID`, for example
   `pick-<hostname>-01`. It must be different on every machine.
4. **Whether they have a registration token** (`ott_...`), or will approve the
   connector by hand in Studio. They keep the token to themselves.
5. **One internal hostname** the connector must resolve, and **one known-live
   target with an open TCP port** on the network to be tested, for the
   network checks. Optional, but without them preflight cannot check DNS or
   reachability.
6. **Whether they plan discovery scans** (mDNS, SSDP, ARP, packet capture,
   Wi-Fi). These need host networking, which is a scope decision
   ([Step 8](#step-8-scope-decisions)).

## Step 1: Confirm the host

Say: this checks the operating system and whether Docker is installed.

```bash
uname -s
docker --version
docker compose version
```

Expected: `Linux`, then a Docker version, then a Compose version. If Docker
is missing, the install guide's step 0 installs it; ask before you follow it
(rule 9), because it uses `sudo`. If `uname -s` does not print `Linux`, go
back to question 1 in [What to ask first](#what-to-ask-first).

## Step 2: Get the files

Say: this makes a `pick-connector` folder and downloads four files from the
release: the compose file, the settings template, the preflight check, and
this runbook.

```bash
PICK_VERSION=0.1.14
mkdir -p pick-connector && cd pick-connector
base="https://github.com/Strike48-public/pick/releases/download/v${PICK_VERSION}"
curl -fsSL "$base/pick-docker-compose.yml" -o docker-compose.yml
curl -fsSL "$base/pick-docker.env.example" -o .env.example
curl -fsSL "$base/pick-docker-preflight.sh" -o preflight.sh
curl -fsSL "$base/pick-docker-agent-setup.md" -o AGENT_SETUP.md
chmod +x preflight.sh
ls -a
```

Expected: `ls -a` lists `.env.example`, `AGENT_SETUP.md`,
`docker-compose.yml`, and `preflight.sh`. If you are already in a folder that
holds these files, skip the `curl` lines but still run `chmod +x preflight.sh`
and `ls -a`: a copied file can lose its execute permission. Run every later
command from this folder.

## Step 3: Run preflight

Say: this checks Docker, outbound connections, and the network, and changes
nothing. Use the answers from [What to ask first](#what-to-ask-first). Leave
out `--resolve` or `--target` if the person did not give one, and add
`--discovery` only if they plan discovery scans. `<studio-host>` and
`<auth-host>` are hostnames, for example `studio.example.com`; a pasted
`https://` URL also works.

```bash
./preflight.sh --studio <studio-host> --auth <auth-host> \
  --resolve <internal-hostname> --target <known-live-ip>:<open-port>
```

Expected: every line is `PASS`, `WARN`, or `SKIP`, and the last lines are:

```
N passed, N warnings, 0 failed.
No blocking problems found.
```

For each `FAIL`, read out the check and its `Fix:` line in plain words,
propose the change, and wait for the go-ahead before you make it (rule 9).
Then run preflight again. For each `WARN`, tell the person what it means for
them and let them decide whether to act on it. Do not work around a `FAIL`.

Do not conclude that a firewall is to blame from a check that only timed out.
Wrong network mode, a Docker subnet overlap, and host DNS all look like a
firewall from inside a container, and preflight checks each of them.

## Step 4: Create .env

Say: this copies the template to `.env` and fills in the three values that are
not secret. You write them with `sed`, which changes the file without printing
it.

```bash
cp .env.example .env
sed -i \
  -e 's|^STRIKE48_HOST=.*|STRIKE48_HOST=wss://<studio-host>|' \
  -e 's|^STRIKE48_API_URL=.*|STRIKE48_API_URL=https://<studio-host>/|' \
  -e 's|^STRIKE48_INSTANCE_ID=.*|STRIKE48_INSTANCE_ID=<instance-name>|' \
  .env
```

`<studio-host>` is the hostname alone, with no `https://`, port, or path.

**Stop.** Ask the person to open `.env` in an editor and type their tenant
UUID on the `STRIKE48_TENANT=` line, replacing the zeros. If they have a
registration token, they remove the `#` at the start of the
`STRIKE48_REGISTRATION_TOKEN=` line and paste the token after the `=`. A token
expires fifteen minutes after it is issued, so they paste it just before
[Step 5](#step-5-start-the-connector). Tell them how to use the editor:

```bash
nano .env
```

In `nano`, `Ctrl+O` then `Enter` saves, and `Ctrl+X` quits. Wait until they
say they have saved, then run preflight again:

```bash
./preflight.sh --studio <studio-host> --auth <auth-host>
```

Expected: the `Configuration (.env)` section shows
`PASS  .env has the four required values in the expected shapes`. If it
reports a key, tell the person which key and what is wrong, and ask them to
fix it in the editor. Do not open the file yourself.

## Step 5: Start the connector

Say: this downloads the image, about 1.4 GB, and starts the connector in the
background. It opens no ports.

```bash
docker compose up -d
```

Expected, after a minute or two, the image pull lines and then, last:

```
 Container pick-connector Started
```

In an interactive terminal the same line starts with a check mark.

An error naming `required variable ... is missing a value` means a required
line in `.env` is empty: go back to the stop point in
[Step 4](#step-4-create-env).

## Step 6: Check the logs

Say: this shows the connector's startup lines.

```bash
docker compose logs --no-color | grep -E 'pentest-agent starting|auth:|Registered|\[status\]'
```

Expected, when approving by hand:

```
pentest-agent starting
  auth:      ott (pending approval)
Registered 116 tools
Registering without JWT (pending approval flow)
Registered successfully: matrix:<tenant>:pentest-connector:<instance-name>
[status] Registered
```

The tool count can differ between releases. `Registered` means the connector
has announced itself and is waiting for approval; it cannot run tools yet. The
`Registered successfully` line contains the tenant UUID: do not repeat it back
in the chat.

With a registration token, the connector approves itself. Skip
[Step 7](#step-7-approval-in-studio-stop), and ask the person to put the `#`
back at the start of the token line in `.env` now that the token is spent.

If the lines do not appear, show the person the last 50 log lines with
`docker compose logs --no-color --tail 50` and match them against the
Troubleshooting table in the install guide.

## Step 7: Approval in Studio (stop)

**Stop.** Tell the person:

1. Open Studio and go to **Gateways** (page title **Gateway Configuration**).
2. In **Pending Approvals**, find the row whose instance id is
   `<instance-name>`. Type it in the search box if the list is long.
3. Click the green check button (**Approve**) and confirm **Approve this
   connector?**.

If they do not have Gateways permission, they send `<instance-name>` to their
Studio administrator and ask them to approve it.

Wait until they say it is approved. Do not poll the logs in a loop meanwhile.

## Step 7a: Confirm it is online

Say: this checks that the connector picked up its approval.

```bash
docker compose logs --no-color --since 5m | grep -E 'Sent JWT re-registration|Registered successfully'
```

Expected:

```
Sent JWT re-registration on existing stream (no disconnect)
Registered successfully: matrix:<tenant>:pentest-connector:<instance-name>
```

Then ask the person to confirm that Studio shows the connector as active. Both
together are success. If Studio's card turns red and says the connector has not
reconnected, go to the Troubleshooting table in the install guide.

Now run preflight again with the same `--resolve` and `--target` as in
[Step 3](#step-3-run-preflight). With the container running, it repeats the
DNS and reachability checks from inside the container and checks the network
Docker gave it, which a `WARN` from Step 3 about Docker's address pool may
have predicted:

```bash
./preflight.sh --auth <auth-host> \
  --resolve <internal-hostname> --target <known-live-ip>:<open-port>
```

A `FAIL` here that passed on the host in Step 3 points at the container's
network, not at a firewall. Report it with its `Fix:` line, and leave the
network mode for [Step 8](#step-8-scope-decisions).

## Step 8: Scope decisions

The connector is online. Before the first scan, ask these two questions, one
at a time, and act only on a clear yes:

1. "Do your rules of engagement include private address ranges (`10.x`,
   `172.16.x` to `172.31.x`, `192.168.x`)?" Only on a yes, append the setting:

   ```bash
   printf 'PENTEST_ALLOW_PRIVATE_IPS=true\n' >> .env
   ```

2. "Do you need discovery scans (mDNS, SSDP, ARP, packet capture, Wi-Fi), and
   is this Linux host dedicated to the connector?" Host networking removes the
   network isolation between the connector and the host. Only on a yes to
   both, create the override file:

   ```bash
   printf 'services:\n  pick:\n    network_mode: host\n' > docker-compose.override.yml
   ```

   If `docker-compose.override.yml` already exists, add the `network_mode`
   line under the existing `pick` service instead of replacing the file.

After either change, recreate the container and check it. The approval is
kept.

```bash
docker compose up -d
./preflight.sh --studio <studio-host> --auth <auth-host> \
  --resolve <internal-hostname> --target <known-live-ip>:<open-port> [--discovery]
```

Expected: preflight now also checks from inside the container, with lines
such as `PASS  Container pick-connector resolves <internal-hostname>` and
`PASS  Container pick-connector reaches <known-live-ip> port <open-port>`, and
`0 failed`.

## Step 9: Hand off

Tell the person, in a short summary:

- the connector is online, with its instance id and network mode
- each preflight `WARN` still open and what it means for them
- the scope answers they gave in [Step 8](#step-8-scope-decisions)
- that "Before your first scan" in the install guide covers what to agree
  before scanning: the source address targets will see, notice to the
  target's security team, and cloud provider rules

Do not include the tenant UUID, a token, or any content of `.env` in the
summary.
