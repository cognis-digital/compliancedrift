# Demo 06 — Terraform security group opened to the world

**Source.** Baseline captured from the planned/approved state of the
`web-tier-sg` AWS security group (SSH restricted to the bastion, HTTPS from the
ALB subnet only). `current.json` is the applied state read back from the
provider after a hotfix.

**What happened.** The SSH ingress rule's source was changed from the bastion
host (`10.0.0.10/32`) to `0.0.0.0/0`, and a brand-new ingress rule was added
opening PostgreSQL (5432) to the entire internet.

**Why this demo is interesting.** The new rule appears as an *added* list element
at `ingress.2`, while the loosened SSH rule shows as *changed* entries at
`ingress.1.cidr_blocks.0` and `ingress.1.description`.

**Run it.**

```bash
compliancedrift diff \
  demos/06-terraform-securitygroup/baseline.signed.json \
  demos/06-terraform-securitygroup/current.json \
  --sarif --fail-on-drift > drift.sarif
```

**Expect.** Exit `1`, 1 added + 2 changed. The SARIF output marks the
`cidr_blocks` change at `error` level (it matches the `allowed_cidrs`/network
security heuristic group).

**How to act.** This is exactly the kind of drift a CI gate should block —
re-restrict SSH to the bastion and delete the world-open Postgres rule before
the apply is allowed to merge.
