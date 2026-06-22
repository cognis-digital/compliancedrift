# compliancedrift demos

Each subdirectory is a self-contained, real-use-case scenario: a signed
`baseline.signed.json` (a known-good config wrapped in a tamper-evident
envelope), a `current.json` (the live/drifted config), an optional `ignore.txt`,
and a `SCENARIO.md` explaining where the data came from, what to expect, the
exact command to run, and how to act on the result.

All baselines are real `compliancedrift` envelopes — run `compliancedrift verify
<demo>/baseline.signed.json` and the integrity check passes. The raw
`baseline.json` (un-signed) is kept alongside so you can re-sign or inspect it.

| # | Scenario | Format | What drifted | Shows |
| --- | --- | --- | --- | --- |
| [01](01-k8s-pod-security/) | Kubernetes Deployment | k8s manifest JSON | Pod became privileged / root | nested security context, added capabilities |
| [02](02-postgres-hardening/) | PostgreSQL settings | `postgresql.conf`/`pg_hba` JSON | TLS off, `trust` from `0.0.0.0/0` | scalar + list-of-rule drift |
| [03](03-s3-bucket-policy/) | AWS S3 bucket | bucket config JSON | Public access unblocked, KMS dropped | removed key + changed flags |
| [04](04-nginx-tls/) | Nginx TLS server block | nginx config JSON | TLSv1/1.1 re-enabled, HSTS removed | positional **list** drift |
| [05](05-sshd-config/) | OpenSSH daemon | `sshd_config` JSON | Root + password login re-enabled | flat config hardening regression |
| [06](06-terraform-securitygroup/) | AWS security group | Terraform state JSON | SSH/Postgres opened to world | added list element + `--sarif` |
| [07](07-docker-daemon-cis/) | Docker daemon | `daemon.json` JSON | ICC on, TLS verify off | **ignore file** workflow |
| [08](08-feature-flags-noise/) | Feature-flag service | flag config JSON | Flag flip vs. telemetry noise | tuning ignore to your risk model |
| [09](09-rbac-roles/) | RBAC policy | RBAC JSON | Wildcard verbs, escalation enabled | removed list elements + changes |
| [10](10-firewall-egress/) | Host firewall | firewall config JSON | Default-deny egress opened | `--sarif` error escalation |

## Run them all

From the repo root (with `compliancedrift` installed, or `PYTHONPATH=src`):

```bash
for d in demos/*/; do
  echo "== $d =="
  ig=""; [ -f "$d/ignore.txt" ] && ig="--ignore-file $d/ignore.txt"
  compliancedrift diff "$d/baseline.signed.json" "$d/current.json" $ig --fail-on-drift
done
```

Every demo (except 08, which has no `--fail-on-drift`) exits `1` because each
contains real drift — that is the point.
