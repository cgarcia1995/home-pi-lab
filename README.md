# Raspberry Pi 5 Home SOC Lab

A hands-on security operations lab I built on a Raspberry Pi 5 while studying for CompTIA Network+ and Security+. It runs real detection and monitoring tools, and every incident and finding gets a documented write-up. The goal was a fully working home SOC — DNS filtering, a default-deny firewall, intrusion detection, and a SIEM — that I can actually operate and investigate with, not just install.

The investigations under `docs/investigations/` are the part I'm proudest of. They show not just that I stood the tools up, but that I can operate them, troubleshoot them when they fail, and make real tuning decisions.

## Architecture

```
[Internet] ── [ISP Gateway 10.0.0.1] ── LAN 10.0.0.0/24
                                          ├── Raspberry Pi 5 "Cris-pi" (10.0.0.169)
                                          │     ├── Pi-hole (Docker) — DNS filtering :53, web :8080
                                          │     ├── nftables — default-deny host firewall
                                          │     ├── Suricata — intrusion detection (IDS)
                                          │     └── Loki + Promtail + Grafana — SIEM / dashboards
                                          ├── MacBook Pro (admin workstation / scan source)
                                          └── Other LAN clients
```

## How Detection Flows

```
Network traffic → Suricata → eve.json → Promtail → Loki → Grafana
```

A scan or suspicious packet hits the wire, Suricata matches it against a rule, writes the alert to eve.json, and it flows through the pipeline until it shows up on my Grafana dashboard. Building that full chain end to end and proving it works was the core goal of the monitoring side.

## Completed

**Headless Linux server** — Raspberry Pi OS Lite (64-bit), administered exclusively over SSH with ed25519 key authentication; password and root login disabled.

**Pi-hole DNS sinkhole** — deployed via Docker Compose with configuration as code (FTLCONF environment variables); serves multiple LAN clients; blocking verified against known ad/tracking domains.

**Default-deny nftables firewall** — dual-stack (IPv4 + IPv6) inet table; inbound allows only SSH, DNS, and the Pi-hole UI from the LAN; all drops logged with counters.

**Vulnerability remediation** — discovered default-enabled rpcbind (111/tcp) listening on all interfaces; disabled and stopped both the service and its activation socket; verified closed via external rescan (full cycle in [docs/NOTES.md](docs/NOTES.md)).

**Scan-based validation** — external nmap from a separate host confirms exactly three exposed ports (22, 53, 8080); host drops discovery probes (requires -Pn), demonstrating default-deny posture.

**Suricata IDS with custom rules** — authored scan-detection signatures (SID 1000001–1000003) and validated them against live scans. See Investigation 01.

**SIEM pipeline** — Loki + Promtail + Grafana ingesting Suricata logs, with a live alerts dashboard.

## Investigations

**[Investigation 01 — Port Scan Detection](docs/investigations/investigation-01-port-scan-detection.md)**
Wrote a custom Suricata rule to detect port scans, found it wasn't firing, and troubleshot it end to end — traced a silent failure to a missing rules file and a HOME_NET direction mismatch, fixed both, and confirmed detection against a live Nmap scan. Mapped to MITRE ATT&CK T1046.

**[Investigation 01b — False Positive Tuning](docs/investigations/investigation-01b-dhcp-tuning.md)**
Noticed benign DHCP alerts firing hourly from my gateway and suppressed them surgically — by signature and source — so the noise stops without losing detection coverage elsewhere.

## Skills Demonstrated

Intrusion detection (Suricata, custom rule writing), SIEM and log pipeline (Loki, Promtail, Grafana), detection engineering and troubleshooting, alert tuning and false-positive management, MITRE ATT&CK mapping, network scanning (Nmap), DNS filtering (Pi-hole), firewalling (nftables, default-deny), vulnerability remediation, Docker and Docker Compose, Linux administration, SSH hardening, and Git version control.

## Roadmap

- [x] Suricata IDS — deployment, custom rules
- [x] SIEM — Loki + Promtail + Grafana with Suricata log integration
- [x] Investigation write-ups — scan detection, false-positive tuning
- [ ] Investigation — simulated SSH brute-force detection
- [ ] WireGuard VPN — remote access with split-tunnel DNS via Pi-hole
- [ ] Internal vulnerability assessment report (full network)

## Repo Layout

- `pihole/` — Docker Compose configuration (secrets sanitized)
- `firewall/` — nftables ruleset
- `docs/investigations/` — incident write-ups with evidence
- `docs/NOTES.md` — earlier findings and lessons learned
- `docs/screenshots/` — evidence: dashboards, scan results, drop logs

## A Note on Ethics

Everything here is authorized testing on equipment I own. Scanning or attacking systems you don't own is illegal — this lab exists specifically so I can practice safely on my own infrastructure.
