# Git push acceptance extension

Status: foundation in place in the coordinated local Heddle/API/Weft integration.
This document does not claim a published release or deployed gateway.

`GIT_PUSH_ACCEPTANCE_V1` is mandatory feature 2, negotiated alongside feature 1
with protocol version 2. `PublishContentOpen.git_acceptance` must not be ignored
by an ordinary source publisher. Whole-history clients use the dedicated sender,
which checks the exact negotiated features and validates the final native receipt.

The outer source names the accepted tip. `GitPushAcceptance.history` lists all
other complete revision uploads in native parent-before-child order, each with
its own ordinary source manifest and operation ID. Indexed `GitPushHistoryFrame`
messages carry those uploads; every inner Finish precedes outer Finish. Receivers
apply cumulative bounds across the entire command, not independent per-tip limits.

The expected native head, mandatory-present server-observed native generation,
and expected/accepted Git SHA-1 commit IDs are checked
by the receiver against validated canonical source closure. `gateway_publisher`
must be the current proof key of an independently authenticated native publisher.
The Git actor comes from the opaque transport session's registered-root/current
owner verification. Wire actor claims do not establish that identity.

`git_acceptance::request_digest` binds the entire logical opening and verified
actor account, with outer/child checkpoints and the transport token removed. The observed native
generation is retained and must not be replaced with the hydrated local replica
generation or refreshed during replay of an accepted command.
The derive-key domain is `heddle.git.acceptance.request.v1`; logical protobuf bytes
and actor UTF-8 bytes are each prefixed with an unsigned little-endian u64 length.
Credential digests in receipts are audit evidence and do not prevent a currently
valid same-actor renewed credential from retrying identical intent.

The mandatory 32-byte `originals_digest` commits to the complete signed operation
manifest across the tip and all historical uploads, including retained originals.
The shared `git_acceptance::originals_digest` helper sorts by the verified 32-byte
operation ID; byte-identical repetitions deduplicate, while conflicting canonical
or signature bytes for the same ID reject. Its BLAKE3 derive-key domain is
`heddle.git.acceptance.originals.v1`, followed by the distinct-count u64 LE and,
for each sorted original, length-prefixed ID, canonical bytes, and signature bytes
(each length is u64 LE). Empty or oversized manifests reject. Receivers derive
IDs through native canonical signature verification, compare the complete uploaded
manifest before admission, and bind this digest into the semantic request identity.
A different original manifest cannot silently reuse a prior command receipt.

The receipt distinguishes exact uploaded representations from durable native
source markers. `history` preserves each exact upload inventory and current
publication policy, while `retained_history` reports the same ordered Thread/State
set with the independently loaded native first inventory and its retained Sharing
frontier. A valid ancestor repack may differ from its existing native marker;
neither is overwritten or silently substituted for the other. Current disclosure
checks the exact retained mapping, and sender validation still binds every uploaded
artifact through the original history receipts and semantic request digest.

A receipt stores both `previous_native_generation` (under the expected-old fence)
and `native_generation` (after admission), so journal recovery can verify both
sides against receiver evidence. A receipt is durable native acceptance, not
proof of current access. Every replay
and `/git/history/authorize` request rechecks the current complete disclosure
closure. The history route accepts exactly one selector: `client_operation_id`
for a genuine prior receipt, or `expected_revision` for explicitly typed native
bootstrap. The bootstrap cannot acknowledge a write. Responses carry actual
server-derived billing owner, verified Spool-genesis digest and current Sharing
frontier under the same authorization/source-generation fence.
