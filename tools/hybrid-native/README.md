The frozen HYBRID native gate uses the newest compatible published native pair: heddle 0.28.6 /
heddle-api 0.31.0-alpha.18. `Cargo.lock` fixes its full dependency graph. It runs as part of
`../../tools/verify.sh`; verification reads fixed vectors and never mints a
Biscuit or regenerates expected bytes.

Run from the API repository root:

```sh
TMPDIR=/home/scratch cargo test --locked --manifest-path tools/hybrid-native/Cargo.toml -- --nocapture
TMPDIR=/home/scratch cargo run --locked --manifest-path tools/hybrid-native/Cargo.toml -- verify tests/fixtures/import-authority-host-witness-v1.json
```

The gate checks native parse/re-encode and original signatures; capture ancestry
and causal/claim dependencies; original account authority; and the existing
hosted request-proof ID, including its original signature. Historical export
verification authenticates the selected signed policy and both branch genesis
admissions. It uses receipt-derived times after witness signature and archive
verification. Export closure remains a reference check, separate from native
authority verification.

The regression input retains verbatim old originals from `acf67659`, including
the closed legacy dispatch negative. This command must exit nonzero:

```sh
TMPDIR=/home/scratch cargo run --locked --manifest-path tools/hybrid-native/Cargo.toml -- verify-capture tests/fixtures/hybrid-native-old-parentless-v1.json
```

Maintenance only, when deliberately changing the reviewed fixture:

```sh
TMPDIR=/home/scratch cargo run --locked --manifest-path tools/hybrid-native/Cargo.toml --bin generate-hybrid-native-biscuit -- tests/fixtures/hybrid-native-biscuit-v1.binpb
TMPDIR=/home/scratch node tools/generate-hybrid-fixture.mjs
```

The generator sends native drafts to the published codecs, then regenerates
native IDs, signatures, typed commitments, receipts, archive roots and paths
together. The Biscuit uses public fixture seeds and contains no appendable proof
secret. Both maintenance commands must reproduce the checked-in bytes exactly.
