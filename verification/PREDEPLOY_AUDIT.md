# Pre-deployment audit

## Current gates

- Contract AST/static/model and Direct Mode suite: 12/12 passing twice consecutively.
- Full public happy path: fetch both artifacts, recompute both digests, package-level consensus, persist `NOTICE_COMPLETE`, reject assessment replay.
- Failure paths: missing attribution, license mismatch, invalid source components, duplicate release, unauthorized remediation and foreign-successor adoption.
- Adversarial paths: one-byte digest substitution, malformed output, prose-wrapped output, unknown token, consequential validator disagreement and prompt-injection fixture.
- Frontend: English-only production build passes; desktop and 390x844 responsive browser inspection passes after mobile header correction.

## Locked fixture identity

Fixture commit: `1b4fa7cd039c3b62d5444c2b06de19d98f6a0158`.

The manifest records exact local bytes, lengths and SHA-256 values. It is not yet public evidence. Before deployment, set the final GitHub repository identity, push this commit, construct Raw GitHub URLs from the full commit SHA, fetch them independently, and update `public_raw_preflight` only after every returned byte sequence matches this manifest.

## Deployment blocker

Do not deploy yet. Public Raw GitHub preflight cannot be completed until the final repository URL is known and the locked fixture commit is pushed.
