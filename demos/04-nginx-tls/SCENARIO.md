# Demo 04 — Nginx TLS downgrade (list drift)

**Source.** Baseline captured from the reviewed TLS server block for
`api.acme.example`. `current.json` is the deployed config after an engineer
"made it work with an old client".

**What happened.** The accepted protocol list was widened to re-enable the
deprecated `TLSv1` and `TLSv1.1`, the cipher suite was loosened to a broad
`HIGH:!aNULL:!MD5`, `prefer_server_ciphers` was disabled, TLS session tickets
were re-enabled, the HSTS header was removed, `X-Frame-Options` was relaxed from
`DENY` to `SAMEORIGIN`, and `server_tokens` now leaks the version.

**Why this demo is interesting.** `ssl.protocols` is a JSON **array** and order is
significant, so the tool reports it as positional drift: indices `0` and `1`
*changed* (the secure protocols shifted down the list) and indices `2`/`3` were
*added*. This shows how compliancedrift treats sequences.

**Run it.**

```bash
compliancedrift diff \
  demos/04-nginx-tls/baseline.signed.json \
  demos/04-nginx-tls/current.json \
  --fail-on-drift
```

**Expect.** Exit `1`, 2 added + 1 removed + 7 changed.

**How to act.** Restore the two-protocol list and the strict cipher suite, and
put back the HSTS header before the next deploy.
