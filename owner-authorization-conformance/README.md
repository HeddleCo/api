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
OWNER_AUTH_SCRATCH=/durable/scratch/owner-auth-corpus \
scripts/owner-authorization-conformance.sh
```

`OWNER_AUTH_CASE_SEED` and `OWNER_AUTH_GRAPH_COUNT` replay or resize the corpus.
CI runs the four pins in `seeds.txt` (96 graphs and more than 1,200 signed
assertions) and logs each seed for replay.

## Verifier artifacts and pins

CI does not check out either private client repository and needs no credential
beyond this repository's default token. It executes four checked-in artifacts:
an ESM bundle of Tapestry's browser verifier and a static Linux x86-64 Heddle
verifier for each profile. `artifacts/SHA256SUMS` makes the artifacts immutable;
the runner checks every digest before execution.

| Profile | Tapestry | Heddle |
| --- | --- | --- |
| `current` | `62f93a187dff4c1e6746b2332f3dcec3f0f52c87` | `ca8a78141c459b95229df2afa25b1c9934f5377c` |
| `pre-fix` | `88d00a6fd5d4dc9b9a091a48992978966e40bb4f` | `68d10ba27a72638a2f8bdd95086c7a2dff79e2e6` |

The normal profile pins the merge commits for Heddle #1140 and Tapestry #248.
Advance those pins and rebuild the artifacts deliberately; never float them.
`artifact-source/tapestry-bridge.ts`, `heddle-verifier`, and
`scripts/build-artifacts.sh` document and reproduce the adapters from local
client checkouts at the selected revisions. Building artifacts requires access
to those repositories, but running conformance does not.

Replay the vulnerability with:

```bash
OWNER_AUTH_PROFILE=pre-fix OWNER_AUTH_GRAPH_COUNT=0 \
  scripts/owner-authorization-conformance.sh
```

The replay must fail the oracle while printing
`SEEDED_VIOLATION=CAUGHT`; the runner converts that expected historical failure
into a successful replay check. The normal profile requires
`SEEDED_VIOLATION=REJECTED_BY_BOTH` and zero divergence.

This is the owner-anchored replacement gate from Weft #248. It does **not**
prove the legacy server-signed grant envelope and does not license flipping
`MIN_BROWSER_SESSION_ISSUED_AT` while that envelope remains the live barrier.
