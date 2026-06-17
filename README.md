# Raspberry Pi 5 Home SOC Lab

Hands-on security lab built while studying for CompTIA Network+ and Security+.
Goal: a fully documented home SOC, DNS filtering, default-deny firewall,
IDS, and SIEM with investigation write-ups for every incident and finding.

## Architecture

```
[Internet] ── [ISP Gateway 10.0.0.1] ── LAN 10.0.0.0/24
                                          ├── Raspberry Pi 5 "Cris-pi" (10.0.0.169)
                                          │     ├── Pi-hole (Docker) — DNS filtering :53, web :8080
                                          │     └── nftables — default-deny host firewall
                                          ├── MacBook Pro (admin workstation / scan source)
                                          └── Other LAN clients
```
## Completed

- **Headless Linux server** — Raspberry Pi OS Lite (64-bit), administered
  exclusively over SSH with ed25519 key authentication; password and root
  login disabled
- **Pi-hole DNS sinkhole** — deployed via Docker Compose with configuration
  as code (FTLCONF environment variables); serves multiple LAN clients;
  blocking verified against known ad/tracking domains
- **Default-deny nftables firewall** — dual-stack (IPv4 + IPv6) inet table;
  inbound allows only SSH, DNS, and the Pi-hole UI from the LAN; all drops
  logged with counters
- **Vulnerability remediation** — discovered default-enabled rpcbind
  (111/tcp) listening on all interfaces; disabled and stopped both the
  service and its activation socket; verified closed via external rescan
  (full cycle in [docs/NOTES.md](docs/NOTES.md))
- **Scan-based validation** — external nmap from a separate host confirms
  exactly three exposed ports (22, 53, 8080); host drops discovery probes
  (requires -Pn), demonstrating default-deny posture

## Roadmap

- [x] Suricata IDS — deployment, custom rule
- [x] SIEM — Loki + Promtail + Grafana with Suricata log integration 
- [ ] Investigation write-ups — simulated brute-force, scan detection
- [ ] WireGuard VPN — remote access with split-tunnel DNS via Pi-hole
- [ ] Internal vulnerability assessment report (full network)

## Repo layout

- `pihole/` — Docker Compose configuration (secrets sanitized)
- `firewall/` — nftables ruleset
- `docs/NOTES.md` — incident/finding write-ups and lessons learned
- `docs/screenshots/` — evidence: dashboards, scan results, drop logs
