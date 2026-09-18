# AttributionGap

AttributionGap is a GenLayer DApp for commit-bound SBOM-to-notice coverage audits. Validators independently fetch a bounded SBOM and `THIRD_PARTY_NOTICES` file from the same immutable GitHub commit, recompute both SHA-256 digests, classify package-level attribution coverage, and reach consensus on structured observations. Contract code derives the final verdict.

## Repository structure

- `contracts/AttributionGap.py` — Intelligent Contract.
- `fixtures/` — bounded public test artifacts; these become immutable only after their Git commit is pinned.
- `tests/` — contract model and static safety tests.
- `frontend/` — English-only release compliance workbench using the supplied logo.
- `verification/` — deployment parity and live lifecycle evidence after manual deployment.

## Security model

The contract does not accept arbitrary evidence URLs. It constructs Raw GitHub URLs from validated owner/repository/full-commit/path components. Each validator fetches and hashes exact bytes. Digest mismatch, malformed evidence, uncertain coverage and unavailable sources cannot produce `NOTICE_COMPLETE`.

The semantic model returns package observations only. It cannot choose the final verdict, alter sealed source identity, or promote an audit. Remediation creates a successor link instead of overwriting history.

## Status

Pre-deployment build. Do not submit a contract address or enable frontend writes until local Direct Mode, public fixture preflight, deployed-source parity and the complete StudioNet live matrix pass.
