# Owner-authorization conformance gate

## Cutover A1 transport corpus

`node tools/verify-owner-authz-cutover.mjs` runs the additive A1 corpus against
the generated `heddle-api` Rust types and `@heddleco/api` TypeScript types. It
checks the canonical sidecar-operation fixture, round trips every new carrier,
proves old Rust pull/token shapes ignore the new fields while retaining known
fields, and compares both languages on signer mismatch, payload swapping,
wrong-spool, transition-fork, rogue UUID binding, incomplete transfer, and
direct/attenuated purge, visibility, and metadata-supersession cases. The
repository-wide `tools/verify.sh` invokes it after both generated targets build.

The pinned Heddle/Tapestry verifier corpus below remains the historical
capability-chain gate. It is repinned to the published shared verifier in A2,
after the A1 API release and downstream preparation changes exist.

This CI harness generates deterministic random owner-capability graphs and
signed child assertions, then gives the same canonical protobuf chains to
Tapestry's browser verifier and Heddle's Rust verifier. It covers action
subsets and supersets, disjoint actions, cross-spool UUIDs, segment siblings,
ancestors, mixed assertion sets, and chain depths 1–6.

The fixed seed `seeded-delegated-purge` is the real violation found while
building the harness: both initial client implementations accepted `purge` in
an attenuated child when its direct owner parent held `grant + purge`. The gate
requires both clients to reject that child while accepting the direct owner
purge.

Run it with:

```bash
TAPESTRY_REV=<full-tapestry-sha> \
HEDDLE_REV=<full-heddle-sha> \
OWNER_AUTH_VERIFIER_ROOT=/durable/cache/owner-auth-verifiers \
OWNER_AUTH_SCRATCH=/durable/scratch/owner-auth-corpus \
scripts/owner-authorization-conformance.sh
```

`OWNER_AUTH_CASE_SEED` and `OWNER_AUTH_GRAPH_COUNT` replay or resize the corpus.
CI runs the four pins in `seeds.txt` (96 graphs and more than 1,200 signed
assertions) and logs each seed for replay.

## Verifier builds and pins

CI checks out each client at an exact commit in runner scratch space. It builds
an ESM bundle of Tapestry's browser verifier and a static Linux x86-64 Heddle
verifier for each profile into `${{ runner.temp }}/owner-auth-verifiers`.
No verifier binaries or generated bundles are committed.

Heddle is public, so its two pinned source builds run in a successful,
independent job with no cross-repository credential. Actions cache stores those
two generated executables under a key containing both Heddle pins and the
adapter sources. The job logs `HEDDLE_VERIFIER_PREP` with `mode=cold` or
`mode=warm` and its elapsed milliseconds.

Tapestry is private. The cross-client job fails explicitly with
`CROSS_CLIENT_CONFORMANCE=UNAVAILABLE` when `secrets.PROJECT_PAT` is absent;
it does not skip the comparison or count unavailable coverage as passed. The
comparison is intentionally gated because agreement is meaningful only when
both distinct client implementations are present. Enabling it is an owner
decision: the minimum credential scope is Contents: read on
`HeddleCo/tapestry`, and nothing more. When present, CI builds and separately
caches both pinned Tapestry bundles in runner scratch.

| Profile | Tapestry | Heddle |
| --- | --- | --- |
| `current` | `62f93a187dff4c1e6746b2332f3dcec3f0f52c87` | `ca8a78141c459b95229df2afa25b1c9934f5377c` |
| `pre-fix` | `88d00a6fd5d4dc9b9a091a48992978966e40bb4f` | `68d10ba27a72638a2f8bdd95086c7a2dff79e2e6` |

The normal profile pins the merge commits for Heddle #1140 and Tapestry #248.
Advance those pins deliberately; never float them.
`artifact-source/tapestry-bridge.ts`, `heddle-verifier`, and the scripts under
`scripts/` document and reproduce the adapters from local client checkouts at
the selected revisions. Only the private Tapestry checkout uses the
cross-repository read credential.

Replay the vulnerability with:

```bash
OWNER_AUTH_PROFILE=pre-fix OWNER_AUTH_GRAPH_COUNT=0 \
TAPESTRY_REV=88d00a6fd5d4dc9b9a091a48992978966e40bb4f \
HEDDLE_REV=68d10ba27a72638a2f8bdd95086c7a2dff79e2e6 \
OWNER_AUTH_VERIFIER_ROOT=/durable/cache/owner-auth-verifiers \
  scripts/owner-authorization-conformance.sh
```

The replay must exit nonzero while printing `SEEDED_VIOLATION=CAUGHT`; CI
requires both that failure status and marker. The normal profile requires
`SEEDED_VIOLATION=REJECTED_BY_BOTH` and zero divergence.

This is the owner-anchored replacement gate from Weft #248. It does **not**
prove the legacy server-signed grant envelope and does not license flipping
`MIN_BROWSER_SESSION_ISSUED_AT` while that envelope remains the live barrier.
