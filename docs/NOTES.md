# Lab Notes — Findings, Incidents, and Lessons

## Finding 1 — Pi-hole rejecting LAN clients ("non-local network")

**Symptom:** Container log warning:
`dnsmasq: ignoring query from non-local network 10.0.0.75`.
A LAN device's DNS queries were being silently dropped.

**Root cause:** Pi-hole runs inside Docker's bridge network (172.17.0.0/16).
From the container's perspective, queries arriving from the real LAN
(10.0.0.0/24) originate from a "non-local" network, and Pi-hole's default
listening mode only answers local-origin queries.

**Resolution:** Set listening mode to allow all origins. First attempt via
CLI failed (see Finding 2); final fix was adding
`FTLCONF_dns_listeningMode: 'all'` to docker-compose.yml and recreating
the container. Exposure risk is mitigated by the host firewall: port 53
only accepts traffic from 10.0.0.0/24.

**Lesson:** Container networking changes what "local" means to a service.
Defense in depth — the permissive service setting is acceptable because a
stricter control (nftables) sits in front of it.

## Finding 2 — Pi-hole v6 configuration hierarchy

**Symptom:** `pihole-FTL --config dns.listeningMode all` returned
`Config option dns.listeningMode is read-only (set via environmental variable)`.

**Root cause:** Pi-hole v6 enforces a configuration precedence:
environment variables > web UI / CLI. Any setting provided via FTLCONF_*
env vars becomes immutable at runtime.

**Resolution:** Moved the change into docker-compose.yml, making the env
var the single source of truth.

**Lesson:** "Read-only" was the system enforcing configuration as code —
the desirable end state anyway. Service config now lives in version control.

## Finding 3 — rpcbind exposure (111/tcp) — full vulnerability cycle

**Detection:** Port scan showed 111/tcp open on the Pi.

**Identification:** `sudo ss -tlnp | grep 111` → rpcbind (PID 690),
bound to 0.0.0.0:111 AND [::]:111 — listening on all interfaces, both
IPv4 and IPv6. Enabled by OS default (`preset: enabled`), not by anything
I installed.

**Assessment:** rpcbind serves NFS/RPC; nothing in this lab uses NFS.
Unneeded service = unnecessary attack surface (least functionality).
rpcbind has a history of recon and amplification abuse.

**Remediation (attempt 1):** `systemctl disable --now rpcbind.service rpcbind.socket`.
Output warned: "Disabling rpcbind.service, but its triggering units are
still active: rpcbind.socket."

**Verification caught a gap:** Due to systemd socket activation, the
socket unit can hold the port and resurrect the service on demand.
Disabling alone did not stop the active socket.

**Remediation (attempt 2):** `systemctl stop rpcbind.socket rpcbind.service`.
Status confirmed both units `inactive (dead)` and `disabled`.

**Final verification:** `ss -tlnp | grep 111` returned nothing on-host;
external nmap from the MacBook showed only 22, 53, 8080 exposed.

**Lessons:**
- A "disabled" systemd service can still be listening via its socket unit.
  Remediation isn't done until verification proves it.
- The dual-stack binding mattered: a firewall covering only IPv4 would have
  left the IPv6 listener exposed. The nftables `inet` table covers both
  families in one ruleset.

## Lesson — Listening vs. Exposed (scan vantage point)

A scan run ON the Pi against itself traverses the loopback path, which the
firewall explicitly allows — it reveals every LISTENING service and bypasses
filtering. A scan from another host must cross the nftables input chain —
it reveals what is actually EXPOSED. The 111/tcp "open" result came from an
on-host scan; the external view never exposed it. Both perspectives are
useful: on-host = service inventory, external = attack surface.

Related: with default-deny in place, the host stopped answering nmap's
discovery probes entirely ("Host seems down"); enumeration required `-Pn`.
Default-deny reduces visibility to casual scanning but is not invisibility —
real attackers scan with -Pn by default.
