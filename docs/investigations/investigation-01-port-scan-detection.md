# Investigation 01 — Port Scan Detection

**Analyst:** C. Garcia
**Date:** 2026-07-07
**Environment:** Home SOC Lab (Raspberry Pi 5)
**Classification:** Simulated / authorized test against own infrastructure
**Status:** Resolved — detection gap identified, remediated, and validated

---

## 1. Summary

During validation of the lab's intrusion-detection capability, an authorized Nmap
port scan was launched from an internal workstation against the lab server. The scan
was initially **not detected**, despite Suricata running and capturing the traffic.
Investigation traced the failure to a custom detection rule that was never persisted
to a loaded rules file, followed by a HOME_NET/EXTERNAL_NET direction mismatch once
the rule was created. After correcting both issues, the scan was reliably detected by
custom signature **SID 1000001**, generating alerts confirmed in fast.log and eve.json.

---

## 2. Environment

| Component | Detail |
|---|---|
| Target host | 10.0.0.169 (Raspberry Pi 5, 8 GB — "Cris-pi") |
| Attacker host | 10.0.0.172 (macOS workstation, authorized) |
| Network | 10.0.0.0/24, monitored interface wlan0 |
| IDS | Suricata (af-packet mode on wlan0) |
| Log pipeline | Suricata to eve.json to Promtail to Loki to Grafana |
| Scan tooling | Nmap -sS (SYN scan), -sV (version scan) |

---

## 3. Detection

**Signature:** LOCAL Nmap SYN scan detected - possible port scan
**SID:** 1000001  **Rev:** 1
**Category:** Attempted Information Leak  **Severity:** 2 (medium)

Rule logic (custom, authored during this investigation):

    alert tcp any any -> $HOME_NET any (msg:"LOCAL Nmap SYN scan detected - possible port scan"; flags:S; flow:to_server; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:1000001; rev:1;)

The rule fires when a single source sends 20 or more SYN-only packets within 10
seconds — a behavioral threshold that distinguishes a normal connection (a handful of
SYNs) from a port sweep (hundreds in rapid succession). Two companion rules (1000002,
1000003) detect anomalous TCP flag combinations (XMAS / SYN+FIN) characteristic of
stealth and version scans.

---

## 4. Timeline (all times PDT, 2026-07-07)

| Time | Event |
|---|---|
| ~21:08 | Initial nmap -sS and -sV scans launched; traffic reached the Pi but no alert generated |
| ~21:09 | eve.json flow record confirmed traffic captured on wlan0 with "alerted": false — detection gap confirmed |
| ~21:10–21:17 | Root-cause analysis: local.rules did not exist; custom rule was never persisted |
| ~21:18 | New local.rules authored and loaded (50755 rules loaded, 0 failed) |
| ~21:20 | First re-test still silent — traced to HOME_NET/EXTERNAL_NET direction mismatch |
| 21:24:31 | Rule corrected to any -> $HOME_NET; first successful alert on SID 1000001 |
| 21:25:01 | Alert confirmed in eve.json with full structured record |

---

## 5. Evidence

**Alert (fast.log):**

    07/07/2026-21:24:31.128731  [**] [1:1000001:1] LOCAL Nmap SYN scan detected - possible port scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.172:37759 -> 10.0.0.169:993

**Structured record (eve.json, key fields):**

| Field | Value |
|---|---|
| timestamp | 2026-07-07T21:25:01.228798-0700 |
| src_ip : src_port | 10.0.0.172 : 39288 |
| dest_ip : dest_port | 10.0.0.169 : 80 |
| proto | TCP |
| in_iface | wlan0 |
| alert.signature_id | 1000001 |
| alert.category | Attempted Information Leak |
| alert.severity | 2 |
| direction | to_server |

Full record: [evidence/inv-01-scan-alert.json](evidence/inv-01-scan-alert.json)

**Screenshots:**
- evidence/inv-01-fastlog-alerts.png — live alerts in fast.log *(add screenshot)*
- evidence/inv-01-grafana-loki.png — same alert surfaced in Grafana/Loki *(add screenshot)*

---

## 6. Analysis

**Activity:** The source host performed a TCP SYN scan across ports 1–1000, followed
by a service/version scan. This is classic reconnaissance — enumerating which ports
are open and what services listen on them, typically the first stage of an attack.

**MITRE ATT&CK mapping:**
- **T1046 — Network Service Discovery** (primary): active enumeration of listening services
- **T1595.001 — Active Scanning: Scanning IP Blocks** (related, reconnaissance phase)

**Why the initial detection failed (two distinct root causes):**

1. **Missing rules file.** Suricata's config referenced local.rules, but the file did
   not exist on disk, so the custom rule was silently skipped at startup. The eve.json
   flow record showing "alerted": false while the traffic was clearly captured was the
   key indicator that isolated this as a rule problem rather than a capture problem.

2. **Direction mismatch.** Once created, the rule used $EXTERNAL_NET -> $HOME_NET.
   Because the attacking workstation (10.0.0.172) is itself inside HOME_NET, its
   traffic never matched the EXTERNAL_NET source condition. Changing the source to
   "any" allowed the rule to match internal-origin test traffic. (Note: the
   EXTERNAL_NET -> HOME_NET form is correct for real internet-borne scans; "any" is
   used here specifically to support internal lab testing.)

---

## 7. Impact

The scan was reconnaissance only — no exploitation was attempted, and Suricata was
operating in IDS (detect) mode, so the alert action was "allowed" (logged, not
blocked). The host firewall (nftables, default-deny) independently limits exposure to
only intended services. Actual risk from this event: low — it is information
disclosure (open-port enumeration), not compromise. In a production context, however,
a scan of this kind is a common precursor to targeted attack and warrants monitoring
for follow-on activity from the same source.

---

## 8. Response & Recommendations

**Actions taken during this investigation:**
- Diagnosed and closed the detection gap (missing rule file + direction logic)
- Deployed and validated three custom scan-detection signatures (SID 1000001–1000003)
- Confirmed the full pipeline: packet to Suricata to eve.json to Loki to Grafana

**Recommendations for a production analogue:**
1. Correlate repeated scans from a single source and alert on frequency, not just occurrence.
2. Consider promoting the Pi to IPS (inline) mode so high-confidence scan sources can be actively dropped rather than only logged.
3. Tune out known-benign noise (see note below) to keep the signal-to-noise ratio high.
4. Feed alert data into a Grafana panel for at-a-glance scan visibility over time.

**Related noise finding:** During monitoring, the gateway (10.0.0.1) was observed
generating hourly "SURICATA DHCP truncated options" alerts — benign DHCP broadcasts
being flagged as malformed. These are false positives and a candidate for suppression
via a threshold/suppress rule, documented separately as a tuning task.

---

*Authorized testing against infrastructure I own. No third-party systems were scanned.*
