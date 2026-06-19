# compliancedrift

**Configuration / compliance drift detector with signed baselines and a CI drift gate.**

`compliancedrift` captures a *baseline* snapshot of your configuration (any JSON
of settings or inventory), embeds a tamper-evident `sha256` digest, and later
compares the live configuration against that baseline to report exactly what has
drifted: keys added, keys removed, and values changed — each reported by its
**dotted path** (e.g. `security.password_policy.min_length`). A built-in ignore
list lets you exclude expected-volatile keys, and a `--fail-on-drift` exit gate
turns the whole thing into a CI guardrail.

- **No dependencies.** Standard library only (`json`, `hashlib`, `argparse`).
- **Original deep diff.** The nested dict/list comparison is implemented here, from scratch.
- **Tamper detection.** A signed baseline's integrity is checked before any diff, so a doctored baseline can't silently mask drift.
- **Defensive / compliance scope.** Detects and reports configuration drift; it does not change your systems.

Maintainer: **Cognis Digital**
License: **COCL 1.0**

---

## Install

```bash
pip install -e .
# or, for development with tests:
pip install -e ".[dev]"
```

Requires Python 3.10+. Once installed you get a `compliancedrift` command; you
can also run it as a module with `python -m compliancedrift`.

---

## Quick start

```bash
# 1. Capture + sign a baseline of your known-good config.
compliancedrift baseline examples/baseline-config.json -o baseline.json

# 2. Later, verify the baseline hasn't been tampered with.
compliancedrift verify baseline.json

# 3. Compare the current config against the baseline and see the drift.
compliancedrift diff baseline.json examples/drifted-config.json

# 4. Use it as a CI gate (non-zero exit when drift is found).
compliancedrift diff baseline.json current.json --fail-on-drift
```

---

## Commands

### `baseline` — capture and sign

```bash
compliancedrift baseline <config.json> -o baseline.json
```

Reads a configuration JSON, normalizes it (recursively sorts dict keys; list
order is preserved because order is significant for sequences), computes a
`sha256` digest over that canonical form, and writes a baseline envelope:

```json
{
  "compliancedrift_baseline": "1",
  "algorithm": "sha256",
  "digest": "9f2c…",
  "config": { "…": "captured configuration" }
}
```

Use `-o -` (or omit `-o`) to write the envelope to stdout. The input may be
`-` to read the config from stdin.

### `verify` — tamper detection

```bash
compliancedrift verify baseline.json
```

Recomputes the digest of the embedded config and compares it to the stored
`digest`. Exit code `0` if intact, `1` if the integrity check fails. Add
`--json` for a machine-readable result:

```json
{"ok": true, "expected": "9f2c…", "actual": "9f2c…"}
```

### `diff` — drift report

```bash
compliancedrift diff <baseline.json> <current.json> [options]
```

Reports drift of `current` relative to `baseline`. The first argument may be a
signed baseline envelope **or** a plain config JSON — if it is a signed
baseline, its integrity is verified first (use `--no-verify` to skip).

Options:

| Option | Description |
| --- | --- |
| `-i, --ignore PATTERN` | Dotted-path glob to ignore (repeatable). |
| `--ignore-file FILE` | File of ignore patterns, one per line (repeatable). |
| `--json` | Emit the drift report as JSON. |
| `--fail-on-drift` | Exit non-zero (`1`) when any drift is detected (CI gate). |
| `--no-verify` | Skip the baseline integrity check before diffing. |

Default (table) output:

```
DRIFT: 1 added, 0 removed, 5 changed

  ? PATH                                       DETAIL
  - ----------------------------------------   ------
  + logging.ship_to                            "syslog://collector.internal"
  ~ logging.level                              "info" -> "debug"
  ~ network.allowed_cidrs.1                    "172.16.0.0/12" -> "0.0.0.0/0"
  ~ network.egress_default                     "deny" -> "allow"
  ~ security.auth.mfa_required                 true -> false
  ~ security.password_policy.min_length        14 -> 8
  ~ security.tls.min_version                    "1.2" -> "1.0"
  ~ service.version                            "2.4.1" -> "2.5.0"
```

`+` added, `-` removed, `~` changed.

JSON output (`--json`):

```json
{
  "has_drift": true,
  "summary": { "added": 1, "removed": 0, "changed": 7 },
  "changes": [
    { "kind": "changed", "path": "security.auth.mfa_required", "old": true, "new": false }
  ]
}
```

---

## Ignore rules

Some keys are *expected* to change between snapshots (timestamps, run ids) and
shouldn't trip the drift gate. Patterns match against dotted paths:

| Pattern | Matches |
| --- | --- |
| `metadata` | `metadata` and anything nested beneath it (`metadata.timestamp`, …). |
| `servers.*.last_seen` | `servers.0.last_seen`, `servers.web.last_seen` (`*` stays within one path segment). |
| `servers.*` | `servers.0` and anything below it (`servers.0.host`). |
| `**.timestamp` | `timestamp` at any depth (`a.b.c.timestamp`). |
| `audit.**.id` | `audit.id`, `audit.events.0.id`, … (`**` spans any number of segments). |
| `v?` | `v1`, `v9` but not `v10` (`?` is a single character). |

Provide patterns inline (`-i metadata.* -i build_id`) and/or from a file
(`--ignore-file ignore.txt`). In a file, blank lines and `#` comments are
skipped. See `examples/ignore.txt`.

```bash
compliancedrift diff baseline.json current.json \
  --ignore-file examples/ignore.txt \
  --fail-on-drift
```

---

## CI gate example

```yaml
- name: Check for configuration drift
  run: |
    compliancedrift verify config/baseline.json
    compliancedrift diff config/baseline.json config/live.json \
      --ignore-file config/ignore.txt \
      --fail-on-drift
```

The job fails (exit `1`) the moment any non-ignored key drifts from the signed
baseline. Exit codes: `0` = OK / no drift, `1` = drift detected or integrity
failure, `2` = usage / IO / parse error.

---

## How the deep diff works

The comparison walks both structures in lockstep:

- **Dicts** of the same type recurse key-by-key. Keys only in the baseline are
  `removed`; keys only in the current config are `added`.
- **Lists** compare index-by-index (order is significant); extra trailing
  elements on either side are `added`/`removed` at their index path.
- A **leaf** (scalar) or a **type mismatch** (e.g. dict → scalar) at a path is a
  single `changed` entry recording `old → new`.

Every entry carries a dotted path so drift is pinpointed precisely. Digests are
computed over a canonical JSON serialization (sorted keys, compact separators,
ASCII-escaped) so a baseline verifies the same regardless of source key ordering
or whitespace.

---

## Development

```bash
pip install -e ".[dev]"
python -m pytest -v
```

On Windows, set `PYTHONUTF8=1` first.

## License

License: COCL 1.0
