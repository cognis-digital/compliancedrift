# Demo 05 — SSH daemon hardening drift

**Source.** Baseline captured from the CIS-aligned `sshd_config` of a bastion
host (key-only auth, no root login, short grace time, modern ciphers).
`current.json` is the running config re-collected during a routine audit.

**What happened.** Root login and password authentication were both re-enabled,
X11 and agent forwarding were turned on, `MaxAuthTries` was raised 3 -> 10,
`ClientAliveInterval` was set to `0` (idle sessions never time out),
`LoginGraceTime` was raised to 120s, weak `aes128-cbc`/`3des-cbc` ciphers were
appended, and the `AllowGroups` allow-list was widened to include `developers`.

**Run it.**

```bash
compliancedrift diff \
  demos/05-sshd-config/baseline.signed.json \
  demos/05-sshd-config/current.json \
  --fail-on-drift
```

**Expect.** Exit `1`, 10 changed paths under `sshd.*`.

**How to act.** Restore `PermitRootLogin no` and `PasswordAuthentication no`
first, then revert the remaining hardening settings and reload sshd.
