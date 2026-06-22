# Demo 02 — PostgreSQL hardening regression

**Source.** Baseline captured from the approved `postgresql.conf` /
`pg_hba.conf` settings of a production database (exported to JSON by the
config-management pipeline). `current.json` is the same settings re-exported
after a contractor "fixed a connection issue".

**What happened.** TLS was turned off (`ssl: on -> off`), the minimum protocol
dropped to `TLSv1`, password hashing was downgraded from `scram-sha-256` to
`md5`, connection logging and statement auditing were disabled, the `pgaudit`
preload was removed, and — worst of all — the host-based auth rule was widened
from `hostssl ... 10.0.0.0/8 scram-sha-256` to `host ... 0.0.0.0/0 trust`,
i.e. unauthenticated access from anywhere.

**Run it.**

```bash
compliancedrift diff \
  demos/02-postgres-hardening/baseline.signed.json \
  demos/02-postgres-hardening/current.json \
  --json --fail-on-drift
```

**Expect.** Exit `1`, 9 changed paths including `parameters.ssl`,
`parameters.password_encryption`, `hba.0.address` and `hba.0.method`.

**How to act.** Treat as an active incident: the `trust`/`0.0.0.0/0` rule must be
reverted immediately, then audit connection logs for the exposure window.
