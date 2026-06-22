# Demo 07 — Docker daemon CIS drift (with an ignore file)

**Source.** Baseline captured from a CIS-benchmarked `daemon.json` plus a small
`snapshot` block of audit bookkeeping that the collector stamps on every run.
`current.json` is the next audit snapshot.

**What happened.** Inter-container communication (`icc`) was re-enabled,
`no-new-privileges` was turned off, user-namespace remapping was cleared, and
daemon TLS verification was disabled. The `snapshot.captured_at` and
`snapshot.audit_run_id` fields also changed — but those are *expected* churn, not
drift.

**Why this demo is interesting.** It shows the ignore-file workflow. Without the
ignore file you get 6 changes (including the noisy snapshot fields); with it you
get exactly the 4 real security regressions.

**Run it.**

```bash
# Noisy: includes expected snapshot bookkeeping.
compliancedrift diff \
  demos/07-docker-daemon-cis/baseline.signed.json \
  demos/07-docker-daemon-cis/current.json

# Clean: ignore the volatile snapshot fields, fail only on real drift.
compliancedrift diff \
  demos/07-docker-daemon-cis/baseline.signed.json \
  demos/07-docker-daemon-cis/current.json \
  --ignore-file demos/07-docker-daemon-cis/ignore.txt \
  --fail-on-drift
```

**Expect.** First command: 6 changed, exit `0` (no gate). Second command: 4
changed (`daemon.icc`, `daemon.no-new-privileges`, `daemon.userns-remap`,
`tls.tlsverify`), exit `1`.

**How to act.** Re-apply the CIS-benchmarked `daemon.json` and restart the
daemon. Keep the ignore file in version control next to the baseline.
