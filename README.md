# blind-operator

Prototype “blind operator” setup: store sensitive artifacts in a local vault and expose only **opaque handles** + **bounded tools** through a reference-monitor gateway, so an LLM/agent can orchestrate workflows without seeing raw bytes.

This repo implements the **opaque-handle + safe-output gateway** part of the pattern (TRE-ish): artifacts are stored by hash, tool calls are audited, and tool outputs are sanitized to avoid returning raw content.

## What it does

- **Vault**
  - Stores blobs at `.blindop/blobs/<sha256>`
  - Stores metadata/audit events in `.blindop/vault.sqlite3`
  - Artifacts are referenced by an opaque UUID **handle** (no content is returned)

- **Gateway (reference monitor)**
  - Centralizes tool invocation (`blindop.gateway.Gateway`)
  - Computes an `input_label` from referenced artifacts/cases
  - Enforces a per-tool `max_input_label`
  - Sanitizes all outputs (`blindop.safe_output.sanitize`)
  - Writes JSONL audit records to `.blindop/audit.log`

## CLI quickstart

State is stored in `./.blindop` by default (override with `--state-dir`).

```bash
python3 -m blindop tools

python3 -m blindop case create --name "IR-123"

# use the returned case_id:
python3 -m blindop ingest --case "<case_id>" --label restricted "/path/to/artifact.log"

python3 -m blindop artifact list --case "<case_id>"
python3 -m blindop artifact show "<handle>"

python3 -m blindop tag add "<handle>" possible_exfil
python3 -m blindop dedupe --case "<case_id>"

python3 -m blindop iocs "<handle>" --include-hashes --top 20
python3 -m blindop timeline --case "<case_id>"
```

## Rulepack scanning

`rulepack scan` runs a constrained regex rulepack and returns **rule IDs only**.

Rulepack JSON format:

```json
{
  "rules": [
    {"id": "has_example", "regex": "example\\.com", "flags": ["i"]}
  ]
}
```

```bash
python3 -m blindop rulepack scan "<handle>" --rules "/path/to/rules.json"
```

## IOC extraction

`iocs` returns aggregate counts and (optionally) **HMAC-SHA256 pseudonyms** for top values so you can correlate across artifacts without revealing raw IOCs.

The HMAC key is stored at `.blindop/hmac.key` (or provide `BLINDOP_HMAC_KEY`).

## Safe outputs (current behavior)

All tool results are passed through a sanitizer:

- `bytes` are replaced with `{ "$redacted": "bytes", "sha256": ..., "len": ... }`
- long strings are replaced with `{ "$redacted": "string", "sha256": ..., "len": ... }`
- deep/large structures are truncated

This is **not** a formal disclosure control system; it’s a practical guardrail for a first prototype.

## Notes / non-goals (for now)

- No TEE/confidential computing; this is a local prototype.
- No network egress controls (assume you wrap this in a stricter sandbox if needed).
- No differential privacy / query budgeting yet.

## Dev

```bash
python3 -m compileall -q blindop
python3 -m unittest discover -s tests -t .
```
