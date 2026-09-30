# Pick Connector - Docker Install Guide

Run the Pick connector as a single Docker container on a host inside your
network, connect it outbound to your Strike48 Studio, and approve it in Studio.
Install takes about ten minutes on a host that already has Docker.

The install, approval, restart, and removal steps in this guide were executed
against a live Strike48 Studio with the `0.1.10` image, and the log lines shown
are what that run printed. The proxy and private-CA sections describe behaviour
read from the connector's source and were not exercised against an appliance.
The network requirements (including IPv6, clock, endpoint security, virtual
machine, and authorization), host networking, Docker Desktop on Windows, and
what-leaves-your-network sections describe Docker's and hypervisors'
documented behaviour, the connector's source, and operational guidance; they were not exercised in
that run. The memory figures were measured separately against a single test
target. The files this guide refers to live in
this repository under [`deploy/docker/`](../deploy/docker/).

## What you are installing

The connector is one container built on Kali Linux that bundles the
penetration-testing toolchain (nmap, nikto, nuclei, ffuf, sqlmap, and more) and
the `pentest-agent` binary. It opens one outbound TLS connection to your Studio
on port 443 and keeps it alive. At start and on each credential refresh it also
makes a short HTTPS call to your Strike48 authentication host, on 443. Nothing
dials in to you.

Because the connection is outbound only, you do not open a firewall port,
publish a hostname, or place the container in a DMZ. The host needs Docker and
egress to two hostnames on 443: your Studio and your authentication host.

On first start the connector registers with your tenant in a pending state and
carries no authority until someone with Gateways permission in your Studio
approves it. Strike48 staff cannot approve it for you.

```mermaid
flowchart LR
  A["Your host<br/>docker compose up -d"] -->|"outbound 443 (wss)"| B["Your Strike48 Studio"]
  B --> C["Studio > Gateways<br/>connector shown as pending"]
  C -->|"you approve"| D["Connector online<br/>credential stored in the volume"]
```

## Before you begin

On the host that will run the connector:

| Requirement | Minimum | How to check |
| --- | --- | --- |
| Docker Engine | a current release (this guide was tested with 29.5) | `docker --version` |
| Docker Compose | v2 plugin (`docker compose`, not the 1.x `docker-compose`; tested with 5.5) | `docker compose version` |
| Outbound HTTPS to Studio | 443 to your Studio hostname | `curl -sS -o /dev/null -w '%{http_code}\n' https://<your-studio-host>/` prints `302` or `200` |
| Outbound HTTPS to authentication | 443 to your Strike48 authentication hostname | `curl -sS -o /dev/null -w '%{http_code}\n' https://<your-auth-host>/` prints a 2xx or 3xx code |
| Outbound HTTPS to the image registry | 443 to `ghcr.io` and `pkg-containers.githubusercontent.com`, which serves the image layers | `docker pull ghcr.io/strike48-public/pick:0.1.10` |
| Outbound HTTPS to GitHub, install time and at run time | 443 to `github.com` and `release-assets.githubusercontent.com`, which the release download redirects to; nuclei downloads its templates from GitHub at run time (see [What leaves your network](#what-leaves-your-network)) | the `curl` commands in step 1 succeed; nuclei template updates work |
| Disk | 8 GB free | `df -h /var/lib/docker` (the `0.1.10` image is about 1.2 GB to download on arm64 and 1.4 GB on amd64, and about 5 GB once unpacked) |
| Memory | 2 GB (recommended floor), 4 GB comfortable | `free -h`. Guidance, not a measured minimum. Measured with the `0.1.10` image against one web target: a full-port nmap scan with version detection peaked at 42 MB, and nuclei with its default templates at about 850 MB, including its first template download. Tools the agent runs in parallel add up, and nuclei grows with concurrency and target count |
| CPU | 2 vCPUs or more | `nproc`. Not a hard minimum; scans take longer on fewer cores |
| Clock | synchronised by NTP or your hypervisor's time sync | `timedatectl` shows `System clock synchronized: yes`. See [Keep the clock in sync](#keep-the-clock-in-sync) |
| Privileges | member of the `docker` group, or root | `docker ps` |
| Architecture | linux/amd64 or linux/arm64 | `uname -m` |
| Local-network discovery | a Linux host running Docker Engine. Docker Desktop on Windows or macOS supports TCP connect scans of routed hosts only; see [Docker Desktop on Windows](#docker-desktop-on-windows) | `uname -s` on the host prints `Linux`. On Windows or macOS, Docker runs in a virtual machine whichever product you use (Docker Desktop, Colima, and others), with similar network limits |

The host does not need a public IP, an inbound DNS record, or a certificate of
its own. If your egress goes through an HTTP proxy or a TLS-inspecting
appliance, read [Corporate proxy and private CA](#corporate-proxy-and-private-ca)
before you start.

### Network requirements for scanning

The table above covers what the connector needs to reach Studio. Scanning has
separate requirements, and they are all properties of the Docker host: the
container reaches your targets through the host's network and resolves names
through the host's DNS configuration. If the host cannot reach or resolve a
target, neither can Pick. Check these on the host before you install.

1. **The host is on the network you want to scan.** Connect it to the VLAN or
   segment in scope, and confirm it can reach a known-live target:

   ```bash
   nc -vz -w3 <known-live-ip> <open-port>
   ```

   If `nc` is not installed, bash can make the same check:

   ```bash
   timeout 3 bash -c '</dev/tcp/<known-live-ip>/<open-port>' && echo open
   ```

2. **The host resolves your internal names.** On the default network, Docker's
   embedded DNS server (`127.0.0.11` inside the container) forwards lookups to
   the DNS servers configured on the host. With
   [host networking](#enable-host-networking) the container shares the host's
   network stack. In both cases a host that points only at a public resolver
   cannot resolve internal names, and scans of those names fail. The
   in-container check at the end of this section confirms what the container
   actually resolves. On the host, confirm with an internal hostname:

   ```bash
   getent hosts <internal-hostname>
   ```

   If this fails, fix the host's DNS first (your DHCP, netplan, or
   systemd-resolved configuration). If the host must keep a different
   resolver, give the container your internal DNS servers in
   `docker-compose.override.yml`:

   ```yaml
   services:
     pick:
       dns:
         - <internal-dns-server-ip>
       dns_search:
         - <internal.example.com>
   ```

3. **Docker uses the network mode your scans need.** The default bridge network
   is enough for TCP and UDP scans of routed hosts. mDNS, SSDP, ARP discovery,
   packet capture, and Wi-Fi scanning need host networking on a Linux host. See
   [Scanning your local network](#scanning-your-local-network-host-networking)
   to choose.

   | Scan type | Default bridge | Host networking (Linux) |
   | --- | --- | --- |
   | TCP/UDP port scans of routed hosts | yes, if the bridge subnet does not overlap your LAN | yes |
   | ICMP ping sweeps | yes | yes |
   | mDNS/Bonjour, SSDP/UPnP discovery | no | yes |
   | ARP discovery, packet capture, Wi-Fi scanning | no | yes |

After the connector is running, repeat the checks from inside the container to
confirm it sees what the host sees:

```bash
docker exec pick-connector getent hosts <internal-hostname>
docker exec pick-connector nc -vz -w3 <known-live-ip> <open-port>
```

A check that works on the host but fails in the container points at the
network mode, a subnet overlap, or the container's DNS settings.

### IPv6 targets

The default network Compose creates for the connector is IPv4 only. Docker
enables IPv6 on a network only when you ask for it, and only on Linux hosts, so
an IPv6 target that the host can reach is unreachable from the container until
you do. If your scope includes IPv6 ranges, either use
[host networking](#enable-host-networking), which gives the container the
host's IPv6 addresses, or enable IPv6 on the connector's network in
`docker-compose.override.yml`:

```yaml
networks:
  default:
    enable_ipv6: true
```

Without a subnet, Docker assigns the network a unique local (`fd00::/8`)
`/64`. Recreate the network with `docker compose down` and
`docker compose up -d`, then confirm from inside the container:

```bash
docker exec pick-connector ip -6 addr show
docker exec pick-connector nc -6 -vz -w3 <known-live-ipv6> <open-port>
```

`PENTEST_ALLOW_PRIVATE_IPS=true` (see
[Scanning private address ranges](#scanning-private-address-ranges)) also
covers IPv6 unique local addresses (`fc00::/7`) and loopback. Link-local
addresses (`fe80::/10`) stay blocked for the web tools either way.

### Keep the clock in sync

At every start and credential refresh the connector signs a short assertion
stamped with the container's current time, valid for 60 seconds, and exchanges
it at your authentication host for a token. It treats a token as expired 30
seconds before its expiry time. Drift breaks this in either direction:

- **Clock ahead of the authentication host, by any amount.** Observed on a
  customer host: the authentication host allows no leeway for a timestamp in
  the future, and the log shows:

  ```
  Token request rejected (400 Bad Request): {"error":"invalid_client","error_description":"Token was issued in the future"}
  ```

- **Clock behind by more than about a minute.** The assertion has already
  expired by the authentication host's clock, and the error may not mention
  time.

When the token request fails, the connector registers without a token
(`RegisterConnectorRequest.jwt_token` is empty), so the log can still say
`Registered successfully` and the gateway can still appear in Studio while
every authenticated call fails. The connector keeps retrying on its own;
nothing is lost and no re-approval is needed once the clock is right.

Containers do not keep their own clock: they read the clock of the Docker
host, or of the Docker Desktop virtual machine on macOS and Windows. Confirm
which side is off by comparing three clocks, with your `STRIKE48_API_URL` in
place of `https://studio.example.com`:

```bash
date -u                                                  # this host
docker run --rm alpine date -u                           # the clock the container sees
curl -sI https://studio.example.com/ | grep -i '^date'   # the Studio's clock
```

If the container clock differs from the `date` header, fix the time where the
container reads it, not in the container:

- Linux host: `timedatectl` should print `System clock synchronized: yes`. If
  it does not, enable NTP (`sudo timedatectl set-ntp true`) or your
  hypervisor's guest time synchronisation. VMs that have been suspended or
  restored from a snapshot are the usual cause.
- Docker Desktop on macOS or Windows: quit and reopen Docker Desktop. Its VM
  clock drifts while the machine sleeps and resyncs when Docker Desktop
  starts.

Then run `docker compose restart`. The next token request succeeds within a
few seconds and the log shows the connector online.

### Endpoint security on the host

The image is built on Kali Linux and contains offensive security tools. An
endpoint detection or antivirus agent on the host, or on the VM, may block the
image pull, quarantine files from its layers, or stop tool processes partway
through a scan. From the connector's side that looks like a tool failing or a
scan ending early, not like a security block. Before the first engagement,
agree an exclusion for the connector with whoever runs endpoint security on
that host: for example Docker's data directory (`/var/lib/docker`) and
processes running in the `pick-connector` container. Check the endpoint
agent's own alerts first when tools fail without a clear error.

### Running Docker inside a virtual machine

If the Docker host is itself a virtual machine (for example a Linux VM on
VMware, Hyper-V, Proxmox, VirtualBox, or a cloud instance), scan traffic passes
through one more layer: the container, then the VM, then the hypervisor or
physical host, then your network. Every layer must be allowed to reach every
system you intend to test. A check that passes on the physical host proves
nothing about the VM, so run the checks above from inside the VM.

**Network access.** Give the VM itself a path to each in-scope system:

- Attach the VM's virtual network adapter to the in-scope segment, with the
  VLAN or port group that segment uses. A bridged or external-switch adapter
  puts the VM directly on that network. A NAT adapter hides the VM behind the
  physical host.
- Allow the traffic through every firewall between the VM and the targets: the
  VM's own firewall, the physical host's firewall, and for a cloud instance its
  security groups, network ACLs, and route tables.
- The VM also needs the Studio and authentication egress in the table at the
  top of [Before you begin](#before-you-begin).

**Authorization.** Targets see the scan coming from the VM's address when its
adapter is bridged, and from the physical host's address when it uses NAT. That
address is the one to record in your rules of engagement, and the one target
owners need to allowlist or expect in their firewall and intrusion-detection
logs. Prefer a bridged adapter with its own address: with NAT, the scan shares
an address with everything else the physical host sends, which makes the
activity harder to attribute. See
[Authorization and notice](#authorization-and-notice) for who else needs that
address.

**Do not clone an approved VM.** The connector's identity is its
`STRIKE48_INSTANCE_ID` in `.env` and the credential stored in the
`pick-connector_pick-state` volume. Cloning the VM, building a template from
it, or running a copy restored from a snapshot duplicates both, and two
connectors then share one identity. Clone or template the VM before the first
`docker compose up`. If a clone already exists, on the clone run
`docker compose down -v`, set a new `STRIKE48_INSTANCE_ID` in `.env`, start it
with `docker compose up -d`, and approve the new entry in Studio.

**Keep the VM running for the engagement.** A VM that is suspended, paused by
the hypervisor, or asleep on a laptop drops its connection to Studio, and any
task running at the time stalls. The connector reconnects when the VM resumes,
but check its clock (see [Keep the clock in sync](#keep-the-clock-in-sync)).

**Limits a VM adds:**

- [Host networking](#enable-host-networking) inside a VM gives the container
  the VM's interfaces, not the physical host's. Layer 2 discovery (mDNS, SSDP,
  ARP) sees only the segment the VM's adapter is attached to, and sees nothing
  of your LAN through a NAT adapter.
- Packet capture needs the virtual switch to pass traffic not addressed to the
  VM. Many hypervisors reject promiscuous mode on a virtual switch by default;
  allow it on the VM's port group if you need capture.
- Some hypervisor NAT modes, in particular user-mode NAT, do not forward raw
  packets faithfully. SYN scans and ICMP ping sweeps through them can report
  hosts as down or ports as filtered when they are not. Use a bridged adapter
  for scanning.

To see the address the VM scans from when its adapter is bridged:

```bash
ip -4 addr show
```

With a NAT adapter, the address targets see is the physical host's, not one
shown inside the VM.

### Authorization and notice

Network access is not permission. Before the first scan:

- **Record the source address.** Put the address targets will see (the host's,
  or the VM's or physical host's as described in
  [Running Docker inside a virtual machine](#running-docker-inside-a-virtual-machine))
  in your rules of engagement, next to the in-scope ranges and the test window.
- **Tell the target's security team.** Scans trigger intrusion detection,
  SIEM alerts, rate limiting, and sometimes automatic blocking. Give the
  target owner's security operations team the source address and the test
  window in advance, so the activity is recognised and the address is not
  blocked partway through the engagement.
- **Check your cloud provider's rules.** If the connector runs in a cloud
  instance, or the targets are hosted in one, the provider's penetration
  testing policy applies as well. Each provider publishes its own, and none of
  them authorises testing assets you do not own. Confirm the engagement fits
  the policy of every provider involved.

### What Strike48 gives you

1. Your **Studio URL**, for example `https://studio.example.com`. The connector
   uses the same hostname you open in a browser.
2. Your **authentication hostname**, for example `auth.example.com`. You do not
   configure it anywhere; Studio hands it to the connector at approval. You need
   it only to allow egress.
3. Your **tenant UUID**, a value shaped like `0192a7c4-3f5e-7b21-9d4a-6e8f0c1b2a3d`.
   It is an identifier rather than a secret, but treat it as internal.
4. Optionally, a **registration token** (`ott_...`) if you want the connector
   pre-approved instead of approving it by hand. Tokens are single-use and
   expire fifteen minutes after they are issued.

There is no registry login. The image is public.

## Install

### 1. Get the bundle

Two files: a compose file you do not edit and an environment template you copy.
Both ship as assets of the release you are installing, so the bundle, this
guide, and the image are pinned to the same version. `0.1.10` is the release
approved for customer use.

```bash
PICK_VERSION=0.1.10
mkdir pick-connector && cd pick-connector
curl -fsSL "https://github.com/Strike48-public/pick/releases/download/v${PICK_VERSION}/pick-docker-compose.yml" -o docker-compose.yml
curl -fsSL "https://github.com/Strike48-public/pick/releases/download/v${PICK_VERSION}/pick-docker.env.example" -o .env.example
```

The compose file from a release defaults to that release's image tag, so you
do not set the tag anywhere. The source of both files is
[`deploy/docker/`](../deploy/docker/) in this repository; the release copy of
the compose file differs only in that default.

### 2. Configure

```bash
cp .env.example .env
$EDITOR .env
```

Fill in the four required values. Everything else in the file is optional and
stays commented out unless you need it.

```bash
STRIKE48_HOST=wss://studio.example.com
STRIKE48_API_URL=https://studio.example.com/
STRIKE48_TENANT=<your tenant UUID>
STRIKE48_INSTANCE_ID=pick-<hostname>-01
```

`STRIKE48_HOST` is your Studio hostname with `wss://` in place of `https://`
and no port. `STRIKE48_API_URL` is the same hostname over `https://` with a
trailing slash. `STRIKE48_INSTANCE_ID` is any stable name for this install; the
approval is keyed to it, so pick something you will not change.

**Use a different `STRIKE48_INSTANCE_ID` on every machine.** If you install on
more than one machine, for example a laptop and a lab server, do not copy the
same `.env` between them unchanged. Two connectors with the same instance id
compete for one identity in Studio, and Studio can show the connector as
offline or fail to open its app.

### 3. Start

```bash
docker compose up -d
```

The first start pulls the image, which takes a minute or two. A missing
required value aborts immediately with a message naming it, for example:

```
error while interpolating services.pick.environment.STRIKE48_TENANT:
required variable STRIKE48_TENANT is missing a value: set STRIKE48_TENANT in .env to your tenant UUID
```

### 4. Check the logs

```bash
docker compose logs --no-color
```

A successful first start ends with these lines. The instance name and tenant
are yours:

```
pentest-agent starting
  host:      wss://studio.example.com
  tenant:    0192a7c4-3f5e-7b21-9d4a-6e8f0c1b2a3d
  instance:  pick-dc1-01
  tls:       true
  auth:      ott (pending approval)
Registered 116 tools
Registering without JWT (pending approval flow)
Registered successfully: matrix:0192a7c4-3f5e-7b21-9d4a-6e8f0c1b2a3d:pentest-connector:pick-dc1-01
[status] Registered
```

`Registered` here means the connector has announced itself and is waiting. It
is not approved yet and cannot run tools.

### 5. Approve in Studio

Open your Studio and go to **Gateways**. The connector appears as a pending
entry identified by the instance id you set in `.env`. Confirm the id matches,
then approve it.

### 6. Confirm

Approval reaches the connector over the connection it already holds. Within a
few seconds the log shows:

```
Sent JWT re-registration on existing stream (no disconnect)
Registered successfully: matrix:0192a7c4-3f5e-7b21-9d4a-6e8f0c1b2a3d:pentest-connector:pick-dc1-01
```

Check with:

```bash
docker compose logs --no-color --since 5m
```

The connector is online when Studio shows it as active. From this point the
approval persists across restarts, upgrades, and host reboots, because the
credential lives in the `pick-connector_pick-state` volume. After a restart the
startup banner still prints `auth: ott (pending approval)` before the stored
credential is loaded; the `Registering without JWT (pending approval flow)`
line no longer appears, and Studio keeps showing the connector as active.

## Configuration reference

All values are read from `.env`. The compose file passes the file through and
pins the security defaults, so a value you set in `.env` for a pinned variable
is ignored.

| Variable | Required | What it does |
| --- | --- | --- |
| `STRIKE48_HOST` | yes | Studio WebSocket endpoint, `wss://<host>`. |
| `STRIKE48_API_URL` | yes | Studio HTTPS origin with trailing slash. The connector posts its registration here, overriding any callback address the Studio advertises. |
| `STRIKE48_TENANT` | yes | Your tenant UUID. |
| `STRIKE48_INSTANCE_ID` | yes | Stable identity of this install. Approval is keyed to `CONNECTOR_NAME` plus this value. |
| `CONNECTOR_NAME` | no | Gateway name shown in Studio. Default `pentest-connector`. Instances sharing a name are load-balanced as one gateway. |
| `PICK_IMAGE_TAG` | no | Image tag. Defaults to the release the compose file was downloaded from. Leave it unset so bundle and image stay one set. |
| `STRIKE48_REGISTRATION_TOKEN` | no | Pre-approval token. See [Pre-approval](#pre-approval-with-a-registration-token). Never leave it set to an empty value. |
| `HTTPS_PROXY`, `NO_PROXY` | no | Standard proxy variables, HTTP CONNECT. Lowercase spellings work too. |
| `MATRIX_TLS_CA_CERT` | no | Path inside the container to an extra CA certificate in PEM format. Added to the system roots. |
| `PENTEST_ALLOW_PRIVATE_IPS` | no | `true` lets tools target RFC 1918 and loopback addresses. See [Scanning private address ranges](#scanning-private-address-ranges). |
| `STRIKE48_TELEMETRY` | no | `0`, `false`, `off`, or `no` turns usage telemetry off. See [What leaves your network](#what-leaves-your-network). |
| `RUST_LOG` | no | Log filter. Default `info,strike48_connector=info`. |

Pinned by the compose file and not configurable from `.env`:

| Variable | Pinned to | Why |
| --- | --- | --- |
| `DISABLE_SANDBOX` | `true` | The image does not ship the in-container tool sandbox; the container is the isolation boundary. |
| `MATRIX_TLS_INSECURE` | `false` | Certificate verification stays on. Use `MATRIX_TLS_CA_CERT` for a private CA. |

## Day-to-day operations

Logs, following, with timestamps:

```bash
docker compose logs -f --timestamps
```

Restart:

```bash
docker compose restart
```

Upgrade to a newer approved release by fetching that release's compose file,
which carries the new image tag as its default. Approval survives because the
volume does:

```bash
PICK_VERSION=<new version>
curl -fsSL "https://github.com/Strike48-public/pick/releases/download/v${PICK_VERSION}/pick-docker-compose.yml" -o docker-compose.yml
docker compose pull
docker compose up -d
```

Setting `PICK_IMAGE_TAG` in `.env` also works, but then the compose file and
the image are no longer from the same release.

Stop without losing the approval:

```bash
docker compose down
```

Remove completely. The `-v` flag deletes the volume holding the credential, so
the gateway in Studio becomes an orphan; remove it there as well.

```bash
docker compose down -v
```

Move to another host: install on the new host with the same `.env`. The
credential stays in the old host's volume, so the connector registers as
pending again and needs a fresh approval. Remove the old host's container first
so two connectors do not share one instance id.

## Pre-approval with a registration token

If Strike48 or your Studio administrator issues you a registration token
(`ott_...`), the connector approves itself on first start and no one has to
visit Gateways.

1. Uncomment `STRIKE48_REGISTRATION_TOKEN` in `.env` and paste the token.
2. Run `docker compose up -d` within fifteen minutes of the token being issued.
3. After the connector is online, comment the line out again. The token is
   spent; leaving it in place does no harm but leaving the variable set to an
   empty value does, because the connector treats an empty token as a token.

## Corporate proxy and private CA

**HTTP proxy.** Uncomment `HTTPS_PROXY` in `.env` and set your proxy URL. The
connector tunnels the WebSocket and its HTTPS calls through an HTTP CONNECT
proxy and honours `NO_PROXY`. Docker itself also needs the proxy for the image
pull; configure that in the Docker daemon or the client config as your
organisation normally does.

**TLS-inspecting appliance or private CA.** Do not disable certificate
verification. Instead, give the connector your CA:

1. Put the CA certificate in PEM format next to the compose file, for example
   `corp-ca.pem`.
2. Create `docker-compose.override.yml` beside `docker-compose.yml`:

   ```yaml
   services:
     pick:
       volumes:
         - ./corp-ca.pem:/etc/pick/corp-ca.pem:ro
   ```

3. Uncomment `MATRIX_TLS_CA_CERT=/etc/pick/corp-ca.pem` in `.env`.
4. `docker compose up -d`.

Compose merges the override automatically. The CA is added to the trust store
the connector already uses, not substituted for it.

## Scanning private address ranges

The connector refuses to point its web tools at RFC 1918, loopback, and
link-local addresses by default. This is deliberate SSRF protection. An
on-premises engagement whose scope includes `10.0.0.0/8`, `172.16.0.0/12`, or
`192.168.0.0/16` needs it relaxed:

```bash
PENTEST_ALLOW_PRIVATE_IPS=true
```

Treat that change as a scope decision recorded in your rules of engagement, not
a troubleshooting step. The cloud-metadata range `169.254.0.0/16` stays blocked
regardless.

## Scanning your local network (host networking)

By default the compose file puts the container on a Docker bridge network that
Compose creates for it, named `pick-connector_default`. The container gets its
own internal subnet and reaches your network through Docker's NAT. That is
enough for the Studio connection and for TCP scans of routed hosts, but it
limits local-network discovery:

- **Multicast discovery returns nothing.** mDNS/Bonjour (`_ipp._tcp.local.`
  and similar) and SSDP/UPnP use multicast, which does not cross the bridge. On
  a bridge network these scans come back empty on every network.
- **Layer 2 discovery and Wi-Fi tools see only the container.** ARP-based host
  discovery, packet capture, and Wi-Fi scanning see the container's virtual
  interface, not the host's Ethernet or wireless adapters.
- **A subnet overlap hides targets.** If Docker assigned the bridge a range
  that overlaps your LAN (Docker's default pools draw from `172.16.0.0/12` and
  `192.168.0.0/16`, and many organisations configure `10.x` pools), traffic to
  those targets stays inside the container and every host looks down.

To check which network the container is on and what subnet it was given:

```bash
docker inspect pick-connector --format '{{.HostConfig.NetworkMode}}'
docker network inspect pick-connector_default --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

### Enable host networking

Host networking puts the container on the host's own network stack, so tools
use the host's interfaces directly. This is the Compose equivalent of
`docker run --network=host`.

1. Create `docker-compose.override.yml` beside `docker-compose.yml`. If you
   already have one (for example for a private CA), add the `network_mode`
   line to the existing `pick` service instead.

   ```yaml
   services:
     pick:
       network_mode: host
   ```

2. Recreate the container:

   ```bash
   docker compose up -d
   ```

3. Confirm the mode:

   ```bash
   docker inspect pick-connector --format '{{.HostConfig.NetworkMode}}'
   ```

   This prints `host`.

The approval is stored in the `pick-connector_pick-state` volume, so the
connector comes back online without a new approval. The `NET_RAW` and
`NET_ADMIN` capabilities in the compose file still apply and are still needed
for raw-socket tools.

### Before you enable it

- **Use a Linux host running Docker Engine.** On Docker Desktop for macOS or
  Windows, containers run inside a virtual machine. Docker Desktop 4.34 and
  later offers host networking as an opt-in setting, but Docker documents it as
  layer 4 only: TCP and UDP work, and protocols below them do not. ICMP, ARP,
  raw-socket scans, and Wi-Fi tools therefore still cannot reach your network
  from Docker Desktop. On a laptop, run the Pick desktop app natively instead.
- **Use a dedicated scanning host.** Host networking removes the network
  isolation between the connector and the host. The connector's internal
  model proxy listens on a loopback TCP port, which is then on the host's
  loopback interface, where other local processes can reach it. Run it on a
  host that only runs the connector.
- **Scope still applies.** Host networking gives the tools reach to every
  network the host can see. Keep targets to the scope recorded in your rules of
  engagement.

If you only need TCP scans and the problem is a subnet overlap, you can keep
the bridge instead: set `default-address-pools` in the Docker daemon
configuration (`/etc/docker/daemon.json`) to a range your network does not use,
for example:

```json
{
  "default-address-pools": [
    { "base": "172.30.0.0/16", "size": 24 }
  ]
}
```

The daemon reads this setting only at start, so restart it, then recreate the
connector's network:

```bash
sudo systemctl restart docker
docker compose down
docker compose up -d
```

Restarting the daemon stops every container on the host, so schedule it. The
`pick-connector_pick-state` volume survives `docker compose down`, so the
approval is kept. Check the new subnet with the `docker network inspect` command above.

## Docker Desktop on Windows

The connector runs on Docker Desktop for Windows, with less network reach than
on a Linux host. Docker Desktop runs Linux containers inside a WSL 2 virtual
machine, and Docker documents that all of that VM's network traffic goes
through NAT in Docker Desktop's backend process (`com.docker.backend`). The
container never sits directly on your LAN, and the
[host networking](#enable-host-networking) option does not change that on
Docker Desktop.

### What works and what does not

| Scan type | Docker Desktop on Windows |
| --- | --- |
| Connection to Studio, approval, tools that talk to the internet | works |
| TCP connect scans of hosts your laptop can route to | works, subject to Windows firewall and VPN rules |
| ICMP ping sweeps, raw-socket (SYN) scans | not documented by Docker; treat results as unreliable |
| mDNS/Bonjour, SSDP/UPnP, ARP discovery, packet capture, Wi-Fi scanning | does not work |

If you need local discovery from a Windows laptop, use the native Pick app for
Windows from the
[releases page](https://github.com/Strike48-public/pick/releases) instead of
Docker. It runs on the laptop's own network interfaces rather than behind
Docker's NAT; packet capture in it needs [Npcap](https://npcap.com/) installed.
For the full discovery toolset, run the connector on a Linux host on the
network you are scanning.

### Requirements

- Docker Desktop with the WSL 2 backend, running **Linux containers** (the
  default). The image is a Linux image and does not run in Windows containers
  mode.
- Windows Defender Firewall, or your endpoint security agent, must allow
  outbound traffic from `com.docker.backend`. Docker notes that host firewalls
  filter Docker Desktop traffic on that process.
- If you are on a VPN, your laptop may reach Studio but not the network you
  are scanning, or the other way round. Check both before you start.

### Install from PowerShell

The install steps above are written for a Linux shell. In PowerShell, use
these equivalents. Use `curl.exe`, not `curl`: in Windows PowerShell 5.1,
`curl` is an alias for `Invoke-WebRequest` and rejects the flags below.

```powershell
$PICK_VERSION = "0.1.10"
mkdir pick-connector; cd pick-connector
curl.exe -fsSL "https://github.com/Strike48-public/pick/releases/download/v$PICK_VERSION/pick-docker-compose.yml" -o docker-compose.yml
curl.exe -fsSL "https://github.com/Strike48-public/pick/releases/download/v$PICK_VERSION/pick-docker.env.example" -o .env.example
Copy-Item .env.example .env
notepad .env
```

In Notepad, fill in the required values and save. Make sure the file is still
named `.env`, not `.env.txt`, and save it as UTF-8 rather than "UTF-8 with
BOM". Then continue with [3. Start](#3-start); the `docker compose` and
`docker exec` commands are the same in PowerShell.

### Check your network from Windows

Run these on the laptop before you install:

```powershell
Test-NetConnection <known-live-ip> -Port <open-port>
Resolve-DnsName <internal-hostname>
```

`TcpTestSucceeded : True` means the laptop can reach the target, and a
returned address means it resolves the name. After the connector is running,
repeat the checks inside the container:

```powershell
docker exec pick-connector nc -vz -w3 <known-live-ip> <open-port>
docker exec pick-connector getent hosts <internal-hostname>
```

If the laptop check passes but the container check fails, the cause is
Docker Desktop's network path: the firewall rule for `com.docker.backend`, the
VPN, or, for names, DNS. For DNS, set your internal DNS servers with the
`dns:` override shown in
[Network requirements for scanning](#network-requirements-for-scanning).

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `required variable ... is missing a value` at `up` | A required line in `.env` is blank or still commented out | Fill it in and run `docker compose up -d` again |
| `Connecting to wss://...` repeats with connection errors | Egress to the Studio host on 443 is blocked, or a proxy is required | Allow outbound 443 to the Studio hostname; set `HTTPS_PROXY` |
| Approved in Studio, but the connector never comes online after a restart | Egress to the authentication host on 443 is blocked | Allow outbound 443 to the authentication hostname Strike48 gave you |
| `Invalid host URL` at startup | `STRIKE48_HOST` points at a private IP or hostname that resolves to one | Use the public Studio hostname. For a private Studio, set `PENTEST_ALLOW_PRIVATE_IPS=true` |
| Connection fails with a port in `STRIKE48_HOST` | Hosted Studios are reached on 443 only; a port copied from a development setup will not answer | Remove the port from `STRIKE48_HOST` |
| TLS or certificate errors in the log | A TLS-inspecting appliance re-signs traffic | Follow [Corporate proxy and private CA](#corporate-proxy-and-private-ca). Do not set `MATRIX_TLS_INSECURE` |
| Logs say `Registered successfully` but nothing appears in Gateways | Wrong `STRIKE48_TENANT`, so it registered against another tenant | Confirm the UUID with Strike48, fix `.env`, `docker compose down -v`, `docker compose up -d` |
| Registration fails right after start with a token in `.env` | The token expired, was already used, or the line is set but empty | Get a fresh token or comment the line out and approve by hand |
| `PENTEST_ALLOW_PRIVATE_IPS is set to an unrecognized value` warning | The variable is set to something other than `true` or `1` | Set it to `true` or comment it out |
| mDNS, SSDP, ARP, or Wi-Fi scans return nothing | The container is on the default bridge network, which multicast and layer 2 traffic do not cross | [Enable host networking](#enable-host-networking) on a Linux host |
| Every host in a known-live range looks down, including TCP ports you know are open | The bridge subnet overlaps your LAN, or Docker Desktop cannot reach the local network | Check the subnet as shown in [Scanning your local network](#scanning-your-local-network-host-networking); change the Docker address pool or enable host networking |
| Scans of internal hostnames fail but the same targets work by IP | The host's DNS does not resolve internal names, so the container cannot either | Fix the host's DNS, or set `dns:` in an override. See [Network requirements for scanning](#network-requirements-for-scanning) |
| The agent reports no live hosts on a network you know is up, or says a firewall is dropping ICMP | The container cannot reach or resolve the targets: wrong network mode, a subnet overlap, host DNS, or Docker Desktop's network limits. A scan that only times out is not evidence of a firewall | Run the host and in-container checks in [Network requirements for scanning](#network-requirements-for-scanning). On Windows, see [Docker Desktop on Windows](#docker-desktop-on-windows) |
| Targets are reachable from the physical host but not from the connector, and Docker runs in a VM | The VM's adapter is not on the in-scope segment, or a VM, host, or cloud firewall blocks it | Run the checks inside the VM and fix its adapter and firewall rules. See [Running Docker inside a virtual machine](#running-docker-inside-a-virtual-machine) |
| Studio shows `App not found or connector is offline` when you open the connector | The connector is not approved or not connected, or two installs share one `STRIKE48_INSTANCE_ID` | Check the Gateways page for the connector's state and for duplicate entries. Give each machine its own `STRIKE48_INSTANCE_ID`, restart it, and approve the new entry |
| `Token request rejected (400 Bad Request)` with `Token was issued in the future`, possibly after `Registered successfully` | The Docker host or Docker Desktop VM clock is ahead of the authentication host's | Compare the three clocks and fix the side that is off. See [Keep the clock in sync](#keep-the-clock-in-sync) |
| Approved, egress to the authentication host works, but authentication fails at start or reconnect | The host clock has drifted, often after a VM suspend, snapshot restore, or laptop sleep under Docker Desktop | Compare the three clocks and enable time sync, or restart Docker Desktop. See [Keep the clock in sync](#keep-the-clock-in-sync) |
| The image pull fails partway, files are missing from the image, or tools stop mid-scan with no clear error | An endpoint security agent on the host is quarantining files or stopping processes | Check that agent's alerts and agree an exclusion. See [Endpoint security on the host](#endpoint-security-on-the-host) |
| The connector goes offline, or switches between online and offline, when another VM starts | A cloned or snapshot-restored VM shares the original's instance id and credential | On the clone, `docker compose down -v`, set a new `STRIKE48_INSTANCE_ID`, start, and approve. See [Running Docker inside a virtual machine](#running-docker-inside-a-virtual-machine) |
| IPv6 targets are unreachable from the connector but reachable from the host | The connector's network is IPv4 only | Enable IPv6 or host networking. See [IPv6 targets](#ipv6-targets) |
| Pending for a long time | Nobody has approved it | Expected. Someone with Gateways permission in your Studio must approve |
| Container restarts in a loop | Malformed `.env` | `docker compose logs`, fix, `docker compose up -d` |

When contacting Strike48 support, include the output of `docker compose ps`
and the last fifty log lines. Redact your tenant UUID if you are sending over
an untrusted channel.

## What leaves your network

- **To your Studio, over the connector's connection.** The AI agent that
  plans the engagement runs in Studio; the connector holds no model. Studio
  sends the connector tool requests, and the connector sends back the output
  of each tool run: discovered hosts, open ports, service banners, HTTP
  responses, findings, and evidence. Returning that output is the connector's
  purpose, so it is not filtered beyond the redaction below. It is stored in
  your tenant in Studio; ask Strike48 about retention and data location.
- **Redaction before it is sent.** The connector replaces credential-shaped
  values it recognises, such as authorization headers, tokens, and passwords,
  in the commands it records and in evidence. This is pattern matching, so a
  secret in a format it does not recognise can still be sent. Do not put
  credentials in a target description or scope note.
- **To your authentication host.** The signed assertion and the short-lived
  token exchange described in [Security notes](#security-notes). No scan data.
- **Usage telemetry.** The connector's code includes optional, pseudonymous
  usage telemetry (an install id, platform, and event names; no targets,
  commands, or results). The `0.1.10` image is built without a telemetry
  endpoint, so it sends none. To keep it off in any build, set
  `STRIKE48_TELEMETRY=0` in `.env`.
- **Tool data.** Some tools fetch their own data at run time. nuclei downloads
  its templates from GitHub the first time it runs, so it needs outbound HTTPS
  to GitHub, or it has no templates to run.

## Security notes

- The container runs as root with the `NET_RAW` and `NET_ADMIN` capabilities so
  that nmap and similar tools can open raw sockets. It has no published ports.
  With [host networking](#enable-host-networking) enabled it shares the host's
  network stack instead of an isolated bridge.
- The connector holds no long-lived bearer token. At approval it stores a
  client identity and a private key in the `pick-connector_pick-state` volume,
  under `/root/.strike48/credentials/` and `/root/.strike48/keys/`, both mode
  0600. At every start it signs a short assertion with that key and exchanges
  it at your authentication host for a short-lived JWT. Back that volume up if
  you want to survive a host rebuild without re-approval.
- `.env` contains no secret unless you add a registration token. Comment the
  token out once the connector is online.
- The connector posts its registration only to the origin in
  `STRIKE48_API_URL`. If the Studio advertises a different callback address,
  the connector logs the override and uses yours.

## Getting help

- Strike48 support: your Strike48 contact.
- Repository: https://github.com/Strike48-public/pick
