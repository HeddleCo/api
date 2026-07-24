# Heddle API

The public protobuf contract shared by Heddle, Weft, and Tapestry. This
repository is the sole owner of schema source, compiled descriptors,
compatibility policy, generation tooling, and Rust/TypeScript releases.

The current wire package is `heddle.api.v1alpha1`. Eleven interfaces are marked
`SHIPPED`; `AgentGatewayService` and `AgentService` are contract-first and
explicitly `PLANNED` for the first release. `OperationService` ships the import
lifecycle; its batch, list, remote-sync, and cancellation capabilities remain
partial.

## Packages

- `heddle-api` — transport-neutral Rust messages, deterministic method
  descriptors/router identities, hosted-call framing, and an additive
  `reflection` feature. It does not generate transport clients or servers.
- `@heddleco/api` — ESM and TypeScript declarations, published to GitHub
  Packages at `npm.pkg.github.com`.

Consumers must exact-pin all `0.x` versions. Generated sources live only in
ignored build staging and release artifacts.

GitHub Packages requires authentication for npm installs. Configure the scope
and provide a classic token with `read:packages` through `NODE_AUTH_TOKEN`:

```ini
@heddleco:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

```sh
npm install --save-exact @heddleco/api@0.2.0
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
