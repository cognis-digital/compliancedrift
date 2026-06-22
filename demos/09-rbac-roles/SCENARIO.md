# Demo 09 — RBAC privilege creep

**Source.** Baseline captured from the reviewed RBAC model (least-privilege
roles, two cluster-admins, escalation disabled). `current.json` is the live
policy re-exported a quarter later.

**What happened.** The `deployer` role's explicit verb list was collapsed to a
single wildcard (`"*"`), the `auditors` binding was changed from the read-only
`viewer` role to `deployer`, the cluster-admin count ballooned from 2 to 9, and
both `allow_wildcard_verbs` and `allow_escalate` were flipped to `true`.

**Why this demo is interesting.** It mixes *changed* values with *removed* list
elements: the `deployer` verb list shrank from 6 entries to 1, so indices `1..5`
are reported as removed while index `0` changed `get -> *`.

**Run it.**

```bash
compliancedrift diff \
  demos/09-rbac-roles/baseline.signed.json \
  demos/09-rbac-roles/current.json \
  --json --fail-on-drift
```

**Expect.** Exit `1`, 5 removed + 5 changed. Key paths:
`rbac.permissions.allow_escalate`, `rbac.permissions.allow_wildcard_verbs`,
`rbac.cluster_admin_count`, `rbac.bindings.auditors`.

**How to act.** Privilege creep — restore the explicit verb lists, move auditors
back to read-only, and re-disable escalation. Investigate who widened the roles.
