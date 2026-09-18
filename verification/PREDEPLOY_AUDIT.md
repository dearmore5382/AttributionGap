# Pre-deployment audit

## Current gates

- Contract AST/static/model and Direct Mode suite: 12/12 passing twice consecutively.
- Full public happy path: fetch both artifacts, recompute both digests, package-level consensus, persist `NOTICE_COMPLETE`, reject assessment replay.
- Failure paths: missing attribution, license mismatch, invalid source components, duplicate release, unauthorized remediation and foreign-successor adoption.
- Adversarial paths: one-byte digest substitution, malformed output, prose-wrapped output, unknown token, consequential validator disagreement and prompt-injection fixture.
- Frontend: English-only production build passes; desktop and 390x844 responsive browser inspection passes after mobile header correction.

## Locked fixture identity

Fixture commit: `1b4fa7cd039c3b62d5444c2b06de19d98f6a0158`.

The manifest records exact bytes, lengths, SHA-256 values and Raw GitHub URLs. All five public URLs at the full fixture commit were independently fetched on 2026-09-18; each returned HTTP 200 and matched both the recorded byte length and SHA-256.

## Deployment blocker

No source-side pre-deployment blocker remains. Deploy only the exact contract source whose SHA-256 is recorded after the final test/build pass, then verify deployed-source parity before sending lifecycle transactions.
