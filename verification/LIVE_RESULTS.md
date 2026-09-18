# AttributionGap StudioNet live results

Contract: [`0x217A62942c968665f2bbF3478434f4a644369723`](https://explorer-studio.genlayer.com/address/0x217A62942c968665f2bbF3478434f4a644369723)

Deployed-source SHA-256 parity: `79c6a76e407f353f35f62a12d43c138dc22ab6acc632790e7acf5482d5b06ede` — verified.

All 18 signed lifecycle steps finalized on StudioNet and were checked against authoritative contract readback.

| # | Scenario | Verified result | Transaction |
|---:|---|---|---|
| 1 | Reject non-pinned commit | `INVALID_SOURCE` | [0x4150…fc8e](https://explorer-studio.genlayer.com/tx/0x4150820e60b978df7a24e9bf5ea5ea65051de1df5b12d37f4a270dff4244fc8e) |
| 2 | Register complete release | audit `0` | [0x538f…208c](https://explorer-studio.genlayer.com/tx/0x538fa874c6eb525004538efc61f11e31ba7882e96763d4fdf1f732c0af28208c) |
| 3 | Reject exact duplicate | `DUPLICATE_RELEASE` | [0x7263…67e2](https://explorer-studio.genlayer.com/tx/0x7263ab93c0f7f7bf5dca3cd322222cbc00fd5990b4810e582d3b76ac829967e2) |
| 4 | Happy path assessment | `NOTICE_COMPLETE` | [0xf274…9239](https://explorer-studio.genlayer.com/tx/0xf27482ef8b1c9473f5e0adc3d6f88634f3c63e314adff0c0b88833364c0a9239) |
| 5 | Reject assessment replay | `AUDIT_NOT_ASSESSABLE` | [0x429b…78ba](https://explorer-studio.genlayer.com/tx/0x429bf561793ae0c91e91789f9ddadcb84f976e47fe36fa7aeab4fe11a35f78ba) |
| 6 | Register missing-attribution release | audit `1` | [0x8221…c0fa](https://explorer-studio.genlayer.com/tx/0x8221570e03fe592344401e2e9072080c702a3ba027296bd22abfa12c82d7c0fa) |
| 7 | Missing attribution | `ATTRIBUTION_GAPS` | [0x173e…4e35](https://explorer-studio.genlayer.com/tx/0x173eb99cd6519d301b56bfcf3e5c1c87f38787cff3726f8b7c2c4b5e09e94e35) |
| 8 | Register wrong-license release | audit `2` | [0x6301…5112](https://explorer-studio.genlayer.com/tx/0x6301c44c1987f5e763aad5cc4191c064ad17baa44aa6a83c71dd966b68aa5112) |
| 9 | License conflict | `LICENSE_MISMATCH` | [0x22af…7730](https://explorer-studio.genlayer.com/tx/0x22af8310d52950ed7e6de6abbc3cd5b8c7ba41a9bc4f1d0cfe3f969ad8277730) |
| 10 | Register false digest | audit `3` | [0x67b7…b695](https://explorer-studio.genlayer.com/tx/0x67b77abf5a460d1ccd98dfdd2f7d5dbb6e23b084ec2695b8593327bb40e9b695) |
| 11 | Digest substitution | `INTEGRITY_FAILURE` | [0xd859…ec12](https://explorer-studio.genlayer.com/tx/0xd859e65758ff41e681bb36c131d196800ed0e240b9378749fbb1439d68c0ec12) |
| 12 | Register unavailable source | audit `4` | [0x82cb…2c46](https://explorer-studio.genlayer.com/tx/0x82cb1b94fcd8d9cd966900dd3a64f0e5c293d7f7697163576d433bf8748d2c46) |
| 13 | Unavailable source | `ASSESSMENT_RETRYABLE`; record remains `REGISTERED` | [0x4629…ae5e](https://explorer-studio.genlayer.com/tx/0x4629d4b0bd50953ebde866b2d4a3dc66aee20b3f517275e4c7a793dd818bae5e) |
| 14 | Register remediation | audit `5` | [0xd0fa…1575](https://explorer-studio.genlayer.com/tx/0xd0fad3f411731cf832b6d489dadce0e9e8bfddf09166735e4c95626903381575) |
| 15 | Assess remediation | `NOTICE_COMPLETE` | [0xfc74…8ac2](https://explorer-studio.genlayer.com/tx/0xfc742496e8ad4f53c9a35fe8c072dae7f7522558159ad6f18dda92301ff48ac2) |
| 16 | Reject outsider remediation link | `CREATOR_ONLY` | [0xd5d3…b350](https://explorer-studio.genlayer.com/tx/0xd5d30b6e0cdbe884c585ec0f8ddb134bca9bf8f81d2de65bd9d1547eabbfb350) |
| 17 | Authorized remediation link | `REMEDIATION_LINKED` | [0xd8d9…f377](https://explorer-studio.genlayer.com/tx/0xd8d99eba35ea5ebb80be348f6ade792aaf0ce969892baaf7728de7e0e023f377) |
| 18 | Reject remediation-link replay | `SUCCESSOR_ALREADY_LINKED` | [0x32c1…fc1f](https://explorer-studio.genlayer.com/tx/0x32c1bda204fabe87e6dfcdc9d6ec65869d7b28937e829f005bd4846fffc6fc1f) |

Final readback: audit count `6`; complete, gap, mismatch and integrity records are terminal; the unavailable-source record remains retryable; audit `1` points immutably to successor audit `5`.
