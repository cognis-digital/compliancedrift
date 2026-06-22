# Demo 08 — Separating product churn from security drift

**Source.** Baseline captured from a feature-flag service config. `current.json`
is the same config after a normal product rollout day.

**What happened.** A feature flag was enabled (`checkout_v2: false -> true`) and a
rollout was bumped to 25%. Telemetry bookkeeping (`last_evaluated`,
`evaluation_id`, `sdk_version`) also changed. The security-relevant setting
`security.flag_admin_mfa` stayed `true`.

**Why this demo is interesting.** This is the "what's actually drift?" case. Pure
telemetry churn is noise and is ignored, but flag and rollout *values* are
intentionally **not** ignored — a flag flip can be a meaningful change you want a
human to see, even if it isn't a security regression. The demo shows how to tune
the ignore list to your risk model rather than silencing everything.

**Run it.**

```bash
compliancedrift diff \
  demos/08-feature-flags-noise/baseline.signed.json \
  demos/08-feature-flags-noise/current.json \
  --ignore-file demos/08-feature-flags-noise/ignore.txt
```

**Expect.** Exit `0` (no `--fail-on-drift` here), 2 changed:
`flags.checkout_v2` and `rollout.checkout_v2_percent`. The three `telemetry.*`
fields are suppressed.

**How to act.** Nothing urgent — review the flag change in the normal change log.
If you wanted the gate to ignore expected flag/rollout churn too, add
`flags.*` and `rollout.checkout_v2_percent` to the ignore file.
