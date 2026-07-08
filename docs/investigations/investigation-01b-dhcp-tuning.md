# Investigation 01b — False Positive Tuning (DHCP)

**Analyst:** C. Garcia
**Date:** 2026-07-07
**Environment:** Home SOC Lab (Raspberry Pi 5)
**Type:** Alert tuning on my own equipment
**Status:** Resolved

## Summary

While watching my logs during Investigation 01, I noticed Suricata firing the same alert once every hour from my router — signature 2227001, "DHCP truncated options." It's harmless: just normal router broadcasts that happen to trip the rule. It was noise, so I suppressed it. The important part is I did it surgically — I silenced that one signature only from the router's IP, so the same alert would still fire from any other source.

## Why It Mattered

False positives are a real problem, not just an annoyance. If an analyst sees the same harmless alert over and over, they start tuning it out in their head, and eventually they miss a real one buried in the noise. Cutting benign alerts keeps the signal clean. The trick is doing it without going blind to actual threats.

## What I Did

The alert was signature 2227001 coming from my gateway at 10.0.0.1, firing hourly (I saw it at 19:48, 20:48, 21:48, etc.). I confirmed the signature ID and source in `eve.json` before touching anything — you never suppress blind.

Then I added a suppression to `threshold.config`:

```
suppress gen_id 1, sig_id 2227001, track by_src, ip 10.0.0.1
```

Read left to right: suppress signature 2227001, tracked by source, but only from 10.0.0.1. Everything else still alerts.

The threshold file wasn't being loaded (the `threshold-file:` line in `suricata.yaml` was commented out), so I enabled it, validated the config with `suricata -T` before restarting (so a typo couldn't take my IDS down silently), and restarted. The log confirmed it loaded: `Threshold config parsed: 1 rule(s) found`. The hourly alerts from the gateway stopped after that.

## The Key Decision

I suppressed by signature *and* source instead of just disabling the rule. Turning the whole rule off would have blinded me to a genuinely malformed DHCP packet from some other host — which could be a real problem. Scoping the suppression to the known-benign source keeps full detection everywhere else. That tradeoff — cutting noise without losing coverage — is the whole point of tuning.

*Authorized tuning on equipment I own.*
