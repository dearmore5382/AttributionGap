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

## Verified StudioNet deployment

- Live DApp: [attribution-gap.dearmorescheuer5382.workers.dev](https://attribution-gap.dearmorescheuer5382.workers.dev)
- Contract: [`0x217A62942c968665f2bbF3478434f4a644369723`](https://explorer-studio.genlayer.com/address/0x217A62942c968665f2bbF3478434f4a644369723)
- Deployed/source SHA-256: `79c6a76e407f353f35f62a12d43c138dc22ab6acc632790e7acf5482d5b06ede`
- Direct Mode: **12 passed**
- StudioNet live lifecycle: **18/18 verified**, including complete coverage, missing attribution, license mismatch, digest substitution, unavailable-source retry behavior, replay protection and authorized remediation.
- Human-readable transaction evidence: [`verification/LIVE_RESULTS.md`](verification/LIVE_RESULTS.md)
- Machine-readable journal: [`verification/live-0x217a62942c968665f2bbf3478434f4a644369723.json`](verification/live-0x217a62942c968665f2bbf3478434f4a644369723.json)

The frontend reads finalized audit records from this contract and exposes wallet-backed registration and assessment writes. Transactions are submitted once; the UI never silently retries a signed write.
