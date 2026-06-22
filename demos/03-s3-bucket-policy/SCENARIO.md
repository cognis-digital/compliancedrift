# Demo 03 — S3 bucket exposed to the public

**Source.** Baseline captured from the IaC-managed configuration of the
`acme-customer-exports` bucket (public-access fully blocked, KMS-encrypted,
versioned, TLS-enforced). `current.json` reflects the live bucket state pulled
via the AWS API after an out-of-band console change.

**What happened.** Three of the four S3 Public Access Block controls were turned
off, the bucket policy now allows public read and no longer enforces TLS,
server-side encryption was downgraded from a customer-managed KMS key
(`aws:kms`) to default `AES256` (the `KMSMasterKeyID` was dropped entirely), and
versioning was suspended.

**Run it.**

```bash
compliancedrift diff \
  demos/03-s3-bucket-policy/baseline.signed.json \
  demos/03-s3-bucket-policy/current.json \
  --fail-on-drift
```

**Expect.** Exit `1`, 1 removed + 7 changed. The removed key is
`encryption.KMSMasterKeyID`; changed keys include all three
`public_access_block.*` flags and `policy.allow_public_read`.

**How to act.** Customer data is potentially world-readable — re-apply the IaC to
restore the Public Access Block and bucket policy, rotate the KMS key if exports
were accessed, and review CloudTrail for `s3:GetObject` from outside the VPC.
