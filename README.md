# Heddle API

The public protobuf contract shared by Heddle, Weft, and Tapestry. This
repository is the sole owner of schema source, compiled descriptors,
compatibility policy, generation tooling, and Rust/TypeScript releases.

The current wire packages are `heddle.api.common` (shared foundational types)
and `heddle.api.v1alpha2` (the frozen Thread-oriented contract). Shared types
such as `CallContext`, `CallFailure`, and `StateId` live in `heddle.api.common`;
versioned services and messages live in `heddle.api.v1alpha2`.

`heddle.api.v1alpha2` is the published Thread/workspace/spool contract: composed
observations, typed local checkout actions, finite content streams, and shared
checkpoint/recovery rules. Rust and TypeScript include transport adapters and
observation lifecycle helpers. Endpoints advertise only implemented handlers.

Read the
[streaming contract and integration gates](docs/alpha-v2/streams.md),
[complete design](docs/alpha-v2/design.md), and
[v1 review inventory](docs/alpha-v2/v1-disposition.csv).

## Packages

- `heddle-api` — transport-neutral Rust messages, deterministic method
  descriptors/router identities, hosted-call framing, and an additive
  `reflection` feature. Typed client adapters target `heddle.api.v1alpha2`.
  The crate does not generate application servers.
- `@heddleco/api` — ESM and TypeScript declarations, published to GitHub
  Packages at `npm.pkg.github.com`.

The versioned treadle CI definition contract and its byte-exact Rust/TypeScript
canonicalization rule are documented in
[`docs/treadle-definition-v1.md`](docs/treadle-definition-v1.md).

Consumers must exact-pin all `0.x` versions. Generated sources live only in
ignored build staging and release artifacts.

GitHub Packages requires authentication for npm installs. Configure the scope
and provide a classic token with `read:packages` through `NODE_AUTH_TOKEN`:

```ini
@heddleco:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

```sh
npm install --save-exact @heddleco/api@0.15.0
```

## Hosted call contract

Native Heddle and Weft use ALPN `heddle-api/1`. One logical call owns one
bidirectional stream. A request is `method_len:u16be | context_len:u32be |
fully_qualified_method | CallContext | body | FIN`; unary responses are an
outcome byte followed by a successful protobuf body or `CallFailure`, delimited
by FIN. Streaming methods retain bounded message framing and explicitly
delimited raw pack/index phases.

`ALL_METHODS` and `method_descriptor` are generated from the same protobuf
descriptors as the messages. They expose type identity, streaming shape,
effect, retry behavior, signing tier, maturity, deployment targets, and the
stable route enum used by application endpoints. Only read-only, safe-retry
descriptors permit 0-RTT.

## Verification

```sh
buf format -d --exit-code
buf lint
python3 -B -m unittest tests/test_operation_contract.py
python3 -B -m unittest tests/test_handle_contract.py
python3 tools/audit_contract.py
cargo check --all-features
npm ci
npm run build
npm run typecheck
```

Apache-2.0 licensed. See [COMPATIBILITY.md](COMPATIBILITY.md) for the pre-1.0
breaking-change policy.
