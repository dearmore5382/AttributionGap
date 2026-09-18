# AttributionGap specification

## Product boundary

AttributionGap records whether a commit-pinned third-party notice covers every package in a bounded SBOM. It does not certify legal compliance, copyright ownership, package safety, or a complete production dependency graph.

## Authority and source binding

- Caller supplies a GitHub owner, repository, exact 40-character commit, two repository-relative paths, and two SHA-256 commitments.
- The contract constructs both Raw GitHub URLs. Arbitrary URLs, branch names, traversal, credentials and alternate hosts are impossible at the public boundary.
- Every validator fetches both artifacts and hashes the exact response bytes before semantic assessment.
- Both artifacts must belong to the same repository and commit.

## Deterministic precedence

1. unavailable source -> `ASSESSMENT_RETRYABLE` and no state mutation;
2. digest mismatch -> `INTEGRITY_FAILURE`;
3. malformed or unsupported SBOM -> `INVALID_EVIDENCE`;
4. any license mismatch -> `LICENSE_MISMATCH`;
5. otherwise any missing attribution -> `ATTRIBUTION_GAPS`;
6. otherwise any unclear observation -> `UNCLEAR`;
7. otherwise -> `NOTICE_COMPLETE`.

## Acceptance matrix

| Class | Fixture | Required outcome |
|---|---|---|
| Happy | complete SBOM + complete notice | `NOTICE_COMPLETE` |
| Failure | one package omitted | `ATTRIBUTION_GAPS` |
| Failure | package attributed under wrong license | `LICENSE_MISMATCH` |
| Integrity | either digest differs by one byte | `INTEGRITY_FAILURE` |
| Availability | missing/dead Raw GitHub path | retryable, unchanged state |
| Adversarial | prompt injection in notice | no privileged positive result |
| Consensus | one consequential package token differs | validator disagreement |
| Replay | assess a finalized audit | `AUDIT_NOT_ASSESSABLE` |

## Lifecycle

`REGISTERED -> FINALIZED`; a later finalized audit at a different commit may be linked once as remediation. Historical audit evidence is never overwritten.
