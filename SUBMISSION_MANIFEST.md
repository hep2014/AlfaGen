# Submission manifest

This archive is intentionally limited to source and reviewable documentation.
It is suitable for the evaluator's ZIP upload and does not contain secrets,
virtual environments, generated datasets, load-test dumps, media, or compiled
artifacts.

## Included

- `src/` — gateway implementation, detector, reversible pair store, HTTP API,
  load client, and benchmark tooling.
- `config/` — example policies and configurable field rules.
- `tests/` — unit, integration, API, overload, retry, and regression tests.
- `docs/` — architecture, jury quick-start, performance methodology, limits,
  policy preview, logging, and PDF-derived requirements.
- `reports/README.md` — index and interpretation of generated measurements;
  generated JSON reports are kept outside the submission archive.
- `data/synthetic/README.md` — description and reproducibility notes for the
  local synthetic benchmark; the generated JSONL dataset itself is excluded.
- `README.md`, `pyproject.toml`, and `process_api.yaml` — setup, run commands,
  evaluator contract, and the complete OpenAPI description.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e '.[dev]'
$env:GATEWAY_API_KEYS = '{"support-demo":"replace-with-a-random-key-of-at-least-32-characters"}'
.\.venv\Scripts\python -m uvicorn alpha_privacy.api:from_env --factory --host 0.0.0.0 --port 8000 --no-access-log
```

The public evaluator calls `POST /process` with
`{"payload":"<string>","payload_id":"<id>"}` and reads
`{"result":"<string>"}`. A retry must reuse the same `payload_id` and payload.
See `README.md` and `docs/resilience.md` for the demo, metrics, retry semantics,
limits, and known limitations.

For a multi-worker launch, set `PROCESS_VAULT_DB` and
`PROCESS_VAULT_KEY_FILE` before starting uvicorn; the shared encrypted SQLite-WAL
vault then keeps a pair available across workers. Without those variables the
default in-memory mode is intended for one process and maximum local throughput.

## Validation snapshot

The working tree was checked with 1104 passing tests. Fresh short load profiles
and their full JSON reports remain in the working tree under `reports/`; they
are deliberately excluded here because the submission format requests source
only.
