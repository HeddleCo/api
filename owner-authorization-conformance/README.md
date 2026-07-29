# Owner-authorization conformance gate

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
No verifier binaries or generated bundles are committed. Actions cache restores
the generated verifiers on later runs, keyed by all four pins.

| Profile | Tapestry | Heddle |
| --- | --- | --- |
| `current` | `62f93a187dff4c1e6746b2332f3dcec3f0f52c87` | `ca8a78141c459b95229df2afa25b1c9934f5377c` |
| `pre-fix` | `88d00a6fd5d4dc9b9a091a48992978966e40bb4f` | `68d10ba27a72638a2f8bdd95086c7a2dff79e2e6` |

The normal profile pins the merge commits for Heddle #1140 and Tapestry #248.
Advance those pins deliberately; never float them.
`artifact-source/tapestry-bridge.ts`, `heddle-verifier`, and
`scripts/build-verifiers.sh` document and reproduce the adapters from local
client checkouts at the selected revisions. The workflow uses the existing
read-only cross-repository app access only on a cache miss.

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
