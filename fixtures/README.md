# Fixtures

## `evidence-pack-sample/`

A minimal, real evidence-pack fixture used by `scripts/verify-tsa-fixture.mjs` to test RFC 3161
timestamp verification fully offline.

**`timestamp.tsr` is a genuine timestamp token**, captured from a real round trip against
`https://freetsa.org/tsr` on 2026-08-08 — not synthesized or hand-built. `manifest.json` and
`report.txt` are the exact content that was timestamped; `manifest.json`'s own bytes are what was
hashed and sent to the TSA.

**This fixture is immutable — do not regenerate it as part of any routine task.** It exists
specifically so timestamp verification can be tested without live network access or dependency on
FreeTSA's uptime. Follows the same pattern used elsewhere in this codebase for protocol/crypto
integrations: do the real round trip once, freeze the resulting bytes, and mock only the transport
layer (here, there's no transport to mock at all at verify time — `verifyTimestampToken()` is pure
offline cryptographic verification against the pinned FreeTSA root CA already embedded in
`verify-pack.ts`).

If this fixture ever needs to be regenerated (e.g. FreeTSA's root CA rotates and the pinned
certificate in `verify-pack.ts` is updated to match), do it deliberately and document why in the
commit — never as an incidental side effect of another change.
