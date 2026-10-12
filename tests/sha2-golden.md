# SHA-2 dependency golden vectors

Captured from `origin/main` at
`a1a4b6e34fc0737bc0cad3d388cc4a2e3fe28dae`, with the direct dependency still
`sha2 = "=0.10.9"`. `ed25519-dalek = "=3.0.0"` already used SHA-2 0.11 for
Ed25519's internal SHA-512. No production implementation or dependency was
changed during capture.

`sha2_golden.rs` calls the contract's implementations on fixed inputs and
compares 196 digest/transcript outputs and 196 deterministic Ed25519 signatures
against hard-coded hex in `fixtures/sha2-golden-main.json`. It uses the existing
checked-in import, native witness, custodial recovery and passkey fixtures,
plus explicit byte arrays, strings and timestamps. Expectations are snapshots
of the old implementation, never recomputed with a second hashing library.
The test rejects missing/added outputs and unknown commitment schemas.

Run all three golden tests, including the private-helper unit tests, with:

```sh
cargo test --locked sha2_golden --lib --test sha2_golden
```

Coverage of SHA-2 call sites and their callers:

| Source | Frozen outputs / verification |
| --- | --- |
| `signing.rs` | One-key device challenge; recovery device proof digest; unary request and stream opening transcripts (including request/capability hashes); nested retry-key digest |
| `password_owner.rs` | Registration verifier possession; mint nonce; password proof; device admission; owner setup; setup authorization; owner key selector checked through the private verifier |
| `passkey_mint_grant.rs` | Exact grant signing digest |
| `timeline_upload.rs` | Derivation path; signed origin identifier; logical upload digest, including its nested origin hash |
| `v2/custodial_recovery.rs` | Email secret and Recover proposal digests; private guardian key selectors exercised by the fixed submission |
| `hybrid_codec.rs` | Empty, split/NUL-containing and multi-block raw hashes; key identifier; canonical signed-payload hashing |
| `import_authority.rs` | All 138 canonical commitment vectors, signed permission/genesis/delegation/operation body digests and signed-record identifiers, owner chain, manifest, content/frontier, conversion options, publication payload, policy state, counted authority envelope and boundary manifest/intent octets |
| `native_witness.rs` | Native genesis body and signed genesis identifier; raw creator envelope and original record hashes; shared authority/landing payload commitments covered by import fixtures |
| `witness_trust.rs` | Witness selector; all four statement purposes and corresponding leaf digests; empty/singleton/even/odd Merkle trees; witness-set digest |
| `writer_authority.rs` | Private retained owner mint-root attachment verifier checks a frozen signature over its SHA-256 digest |

`import_authority::sha2_golden_original_signatures` freezes the private ordered
original-signature commitment with two records and one additional signature.
`writer_authority::sha2_golden_retained_attachment` pins the original signature
bytes and verifies them through the production private hash call; a digest
change therefore invalidates the fixed signature. The integration test also
verifies fixed custody proofs and a password setup authorization through their
production key-selector paths.

The remaining cryptographic identifiers implemented with BLAKE3 are outside
this SHA-2 upgrade. Fixed Ed25519 signing seeds are public test data. The API
does not call SHA-512 directly; the signature snapshots also exercise dalek's
already-upgraded SHA-512 implementation.

Do not refresh these expectations as part of a dependency update. To prove
the assertions detect drift, change one input byte in
`recovery_new_device_pop_digest`, run the golden tests and observe a mismatch;
restore that byte and rerun the same tests unchanged.
