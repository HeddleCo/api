# Timeline owner authorization bundle bound

The `TimelineAdmissionAcceptance.owner_derived_capability` envelope accepts
1..65536 bytes (64 KiB), inclusive. Rust and TypeScript expose this ceiling as
`MAX_TIMELINE_OWNER_BUNDLE_BYTES`. Principal credential IDs remain 1..128 bytes.
The owner bundle's exact bytes are included in the acceptance signing transcript.

The previous 4096-byte ceiling rejected legitimate current owners as their
signed rotation history grew. The new ceiling matches the identity envelope
bound. Consumers still verify the complete canonical bundle, pinned current
owner state, capability, subject Biscuit and subject acceptance signature.

`tests/fixtures/timeline-owner-long-history.json` contains an 11485-byte
format-3 bundle with 20 ordinary rotations followed by a guardian-authorized
recovery and a capability issued by the recovered current key. Its generator
uses the independent Heddle verifier at
`b83f6e83c16cfb0b2f58f6f2b599c25bfe1a65be`. It verifies the bundle against the
current checkpoint and proves that stale state, a tampered transition signature
and a tampered issuer signature fail. The API Rust and TypeScript tests then
check the canonical fixture and acceptance envelope, and independently sign and
verify the acceptance transcript with the capability subject's key. Boundary
tests accept exactly 65536 bytes and reject empty and 65537-byte authorities.

Regenerate with a local read-only Heddle checkout containing that revision:

```sh
TMPDIR=/home/scratch python3 tests/generate-long-owner-history-fixture.py /path/to/heddle
```

Only an ignored disposable copy under `build/long-owner-history-verifier` is
modified. The generator calls the underlying format-3 bundle verifier because
the pinned verifier's timeline envelope still enforces 4096 bytes.

## Consumer follow-ups

Read-only audit of `origin/main` on 2026-09-30:

| Repository / revision | File:line needing the same bound change |
| --- | --- |
| Heddle `b83f6e83c16cfb0b2f58f6f2b599c25bfe1a65be` | `crates/capability-verifier/src/timeline.rs:53` — owner-derived acceptance verifier |
| Heddle (same revision) | `crates/hosted-client/src/hosted_runtime/hosted/timeline_origin.rs:282` — client acceptance signer |

Weft `480cbf77a7769d5ef89037d6139197f362761e7e` has no local copy of this
4096-byte timeline owner-bundle bound and no timeline acceptance verifier call.
Its native dispatch policy explicitly lists the timeline RPCs as unsupported
(`crates/weft-hosted/src/native_dispatch_policy_tests.rs:97-98`), as does the
native service registration test (`crates/weft-hosted/tests/native_service_registration.rs:168-169`).
Its published capability-verifier dependency is pinned to `0.23.0`
(`Cargo.toml:68`); future timeline admission must consume the updated verifier.

Other 4096-byte bounds found in the audit cover origin endorsements, operation
bodies, passwords, owner-key bindings, WebAuthn data, paths or unrelated
pagination/storage sizes. They do not bound the timeline owner bundle.
