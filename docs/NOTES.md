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

**Lesson:** "Read-only" was the system enforcing configuration as code
the desirable end state anyway. Service config now lives in version control.

## Finding 3 — rpcbind exposure (111/tcp)/ full vulnerability cycle

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

## Finding 4 — DNS outage: FORWARD chain blocked container upstream traffic

**Symptom:** dig/nslookup against Pi-hole timed out for all clients. Inside
the container, `pihole status` showed FTL healthy and listening but even
`dig @127.0.0.1` from inside the container timed out.

**Diagnosis path:** ss confirmed port 53 bound (docker-proxy); docker inspect
confirmed correct port bindings; in-container test isolated the failure to
upstream resolution, not the listener.

**Root cause:** The nftables forward chain was `policy drop` with no accept
rules. Container-to-internet traffic traverses FORWARD, so Pi-hole's queries
to upstream DNS were silently dropped since the firewall was enabled.

**Why it was masked:** Cached answers and blocklist hits are served locally
and never need upstream, so earlier tests (cached google.com, blocked
doubleclick.net) appeared healthy. The outage surfaced only after cache
entries expired.

**Fix:** Added to the forward chain: `ct state established,related accept`
and `ip saddr 172.16.0.0/12 accept` (Docker compose bridge range). Also
learned: `flush ruleset` wipes Docker's NAT rules, so any manual
`nft -f` reload must be followed by `systemctl restart docker`.

**Lesson:** Default-deny applies per chain hardening INPUT while
forgetting FORWARD broke the very service the firewall protects. Test with
uncached domains; caches can hide upstream failures.

## Lesson — Listening vs. Exposed (scan vantage point)

A scan run ON the Pi against itself traverses the loopback path, which the
firewall explicitly allows it reveals every LISTENING service and bypasses
filtering. A scan from another host must cross the nftables input chain
it reveals what is actually EXPOSED. The 111/tcp "open" result came from an
on-host scan; the external view never exposed it. Both perspectives are
useful: on-host = service inventory, external = attack surface.

Related: with default-deny in place, the host stopped answering nmap's
discovery probes entirely ("Host seems down"); enumeration required `-Pn`.
Default-deny reduces visibility to casual scanning but is not invisibility —
real attackers scan with -Pn by default.

## Finding 5 — Suricata IDS: capture failure on Wi-Fi (af-packet vs libpcap)

**Goal:** Deploy Suricata as a network IDS, trigger a detection, author a
custom rule. Interface: wlan0 (Pi runs over Wi-Fi; eth0 was down).
HOME_NET: 10.0.0.0/24. Pulled ET Open ruleset (~50k rules) via suricata-update.

**Symptom:** Service showed active (running), config valid, 50k rules loaded,
but a known-good trigger (curl to testmynids.org returning "uid=0(root)")
produced NO alert.

**Diagnosis:** Confirmed the service was genuinely running and the trigger
traffic was real (curl returned the uid=0(root) string). Checked capture
stats in stats.log: `capture.afpacket.polls` == `capture.afpacket.poll_timeout`
(equal counts) — Suricata was attached to wlan0 but receiving zero packets
on every poll.

**Root cause:** af-packet capture mode does not reliably pull traffic from
this Wi-Fi interface/driver. Known limitation of wireless + af-packet.

**Fix:** Switched capture to libpcap. Verified live in the foreground
(`suricata -c suricata.yaml --pcap=wlan0 -v`); the trigger then fired:
`[1:2100498:7] GPL ATTACK_RESPONSE id check returned root` (over IPv6).
Made permanent with a systemd override (`systemctl edit suricata`):

    [Service]
    ExecStart=
    ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pcap=wlan0 --pidfile /run/suricata.pid -D

After daemon-reload + restart, capture.kernel_packets climbs steadily,
confirming live capture as a service.

**Custom rule authored** (/var/lib/suricata/rules/local.rules):

    alert icmp any any -> $HOME_NET any (msg:"LOCAL Custom Rule - ICMP ping detected"; sid:1000001; rev:1;)

sid in the 1000000+ range (reserved for local rules). Triggered with a ping;
alert fired with the custom message and SID. Note: the rule had to live in
/var/lib/suricata/rules/ (the path suricata-update manages) and be listed in
rule-files in suricata.yaml. a first attempt in /etc/suricata/rules/ wasn't
loaded. Also learned: always `cat` a file after a sudo-nano edit; a silent
save failure left local.rules empty the first time.

**Lessons:**
- A running IDS service is not a working IDS — verify it actually captures
  packets (equal poll/poll_timeout counts = listening but receiving nothing).
- Capture method matters: af-packet (fast, wired) vs libpcap (slower, Wi-Fi
  compatible). Speed cost is irrelevant at home-lab volume.
- Detection worked over IPv6 without extra config — dual-stack visibility,
  same theme as the rpcbind finding.


## Finding 6 — Wazuh SIEM: ARM64 incompatibility, informed pivot

**Goal:** Deploy Wazuh single-node (indexer + manager + dashboard) as the SIEM.

**Symptom:** The wazuh.indexer container crash-looped with
`exec /entrypoint.sh: exec format error`, repeating Restarting (255).

**Root cause:** `exec format error` = wrong CPU architecture. The Pi 5 is
ARM64; Wazuh's v4.9.0 indexer/dashboard images are built for x86/amd64.
Wazuh's indexer and dashboard historically lack ARM64 support (the manager
runs on ARM, but the searchable UI components do not).

**Decision:** Rather than force an unsupported config, pivoted to a lighter,
ARM-native stack: Grafana Loki + Promtail + Grafana,same core capability
(centralized log aggregation, queryable dashboards, Suricata integration) on
hardware that actually supports it. Cleanup: `docker compose down -v` and
`docker image prune -a -f` to remove the dead x86 images.

**Lesson:** Check architecture support before deploying. Knowing when to pivot
vs. force a square peg is a real engineering judgment call.

## Finding 7 — Loki + Promtail + Grafana SIEM (Suricata integration)

**Stack:** Suricata eve.json -> Promtail -> Loki -> Grafana. ARM64-native,
lightweight. Added an nftables rule for Grafana (tcp 3000, LAN-only).

**Key issue — Loki ingestion rate limit (429):** Promtail logged
`429 Too Many Requests: Ingestion rate limit exceeded (4MB/sec)`. Suricata's
eve.json logs every DNS/flow/decode event (~19k/hour) — a firehose that blew
past Loki's default limit, dropping batches so the dashboard stopped updating.
Fix: loki-config.yaml raising ingestion_rate_mb to 50 / burst to 100.

**Persistence:** Grafana dashboards initially vanished on container
recreation the service had no volume, so its internal DB reset. Fixed with a
named volume (grafana-data:/var/lib/grafana).

**Dashboard:** 5 panels — Alerts, Total Events, Events by Type, Alerts Over
Time, and a live Suricata Alert Feed. (LogQL note: Stat panels use Instant;
time-series use Range.)

**Verification:** Suricata fast.log shows custom rule 1000001 firing on each
ping; Grafana Explore `{job="suricata"}` returns live parsed JSON with current
timestamps  confirming the full pipeline works end to end.

**Lessons (SOC-relevant):**
- Alert dedup: repeated identical pings produce fewer alerts than packets sent
  — IDS engines aggregate duplicate signatures to prevent alert fatigue.
- Events vs. alerts: total volume != detections. Most traffic (DNS, flows) is
  benign; a SIEM that ingests everything hits volume limits fast (the 429) —
  real deployments filter what they collect.
