# Demo 10 — Host firewall egress opened up

**Source.** Baseline captured from a default-deny host firewall on a payments
worker (egress restricted to the primary DB and the internal vault).
`current.json` is the running ruleset after a change to "unblock an outbound
integration".

**What happened.** The default output policy flipped `DROP -> ACCEPT`,
`egress_default` flipped `deny -> allow`, and the second allow-list entry's
destination was widened from the internal vault (`10.0.9.10/32`) to `0.0.0.0/0`.
On a payments host, unrestricted egress is a textbook data-exfiltration risk.

**Run it.**

```bash
compliancedrift verify demos/10-firewall-egress/baseline.signed.json
compliancedrift diff \
  demos/10-firewall-egress/baseline.signed.json \
  demos/10-firewall-egress/current.json \
  --sarif --fail-on-drift > egress-drift.sarif
```

**Expect.** Exit `1`, 3 changed:
`firewall.default_policy.output`, `firewall.egress_default`, and
`firewall.allowed_egress.1.dest`. In the SARIF output, the `egress_default`
change is `error` level.

**How to act.** Revert to default-deny egress immediately and check connection
logs for outbound traffic to non-allow-listed destinations during the window.
