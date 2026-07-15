# Heddle API

The public protobuf contract shared by Heddle, Weft, and Tapestry. This
repository is the sole owner of schema source, compiled descriptors,
compatibility policy, generation tooling, and Rust/TypeScript releases.

The current wire package is `heddle.api.v1alpha1`. Ten interfaces are marked
`SHIPPED`; `AgentGatewayService`, `AgentService`, and `OperationService` are
contract-first and explicitly `PLANNED` for the first release.

## Packages

- `heddle-api` — Rust types by default; additive `client`, `server`, and
  `reflection` features.
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
npm install --save-exact @heddleco/api@0.1.1
```

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
