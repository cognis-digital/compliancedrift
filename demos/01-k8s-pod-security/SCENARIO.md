# Demo 01 — Kubernetes pod security context drift

**Source.** A signed baseline (`baseline.signed.json`) was captured from the
hardened `checkout-service` Deployment manifest after a security review.
`current.json` is the live manifest pulled back from the cluster
(`kubectl get deploy checkout-service -o json`, trimmed to the fields under
review) a few weeks later.

**What happened.** A "temporary" debugging change to ship a release candidate
(`1.9.0-rc1`) quietly turned the pod into a privileged, root-running container:
`runAsNonRoot` flipped to `false`, `runAsUser` is now `0`, the seccomp profile
became `Unconfined`, `privileged` and `allowPrivilegeEscalation` are now `true`,
`readOnlyRootFilesystem` was disabled, `NET_ADMIN`/`SYS_ADMIN` capabilities were
added, and the service-account token is auto-mounted again.

**Run it.**

```bash
compliancedrift verify demos/01-k8s-pod-security/baseline.signed.json
compliancedrift diff \
  demos/01-k8s-pod-security/baseline.signed.json \
  demos/01-k8s-pod-security/current.json \
  --fail-on-drift
```

**Expect.** Exit code `1` and a table with 1 added + 9 changed paths, all under
`spec.template.spec...securityContext`.

**How to act.** This is a release blocker. Revert the security context to the
baseline values before promoting the RC, or re-review and re-baseline only if the
privilege grant is genuinely required and approved.

Add `--sarif` to upload these as findings to GitHub code scanning — the
privilege-escalation paths are emitted at SARIF `error` level.
