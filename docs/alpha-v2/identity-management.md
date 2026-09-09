# Identity management canonical records

These formats use Ed25519 signatures over UTF-8 format name, one zero byte, then
`canonical_record`. Unknown formats and noncanonical encodings fail closed.
`heddle_api::v2::identity_management` owns the canonical codecs; these are not
signatures over generic protobuf request serialization. Integers are big endian;
variable fields have a u32 byte length; strings are UTF-8.

`heddle.delegation.v2` uses `DelegationStatement`: version1, account UUID string,
delegation UUID string, label, kind(u32), root key, subject key, optional endpoint
key, scope, expiry(i64), and BLAKE3 of the exact parent credential. It contains no
bearer. Empty scope preserves the parent's full ceiling; finite expiry remains
mandatory. Updating its public record cannot discard the original parent chain.

`heddle.delegation-issuance-possession.v2` signs `issuance(account, request)`:
version1, account, operation ID, delegation ID, expected version, child proof key,
scope, then expiry presence(byte) and optional seconds(i64). The authority format
`heddle.delegation-issuance-authority.v2` appends a 64-byte signature over the
existing `heddle-pop-delegation-v1` statement for that exact parent and child key.
The authority signs the whole resulting record; the subject signs the intent.
The server can append the proved delegation and narrower caveats without holding
the user's private key or replacing the original authority block.

`heddle.root-registration-possession.v2` binds account, operation, both keys,
endpoint key, attachment format and canonical attachment body, and label.
Endpoint ownership uses the existing `heddle.root-attachment.v2` verifier too.
`heddle.delegation-revocation.v2` binds account, operation, record and exact version.

Recovery policy/transition records use `heddle.owner-recovery-policy.v2` and
`heddle.owner-recovery-transition.v2`. Their payload is the canonical wire carrier
of an original SignedOwnerKeyTransition; its existing portable owner signatures
are verified by the shared capability verifier. No signature is synthesized by
Weft. Recovery possession/veto formats bind account, operation, attempt, expected
version and proposed key through `recovery_action`. Owner state, threshold, delay,
veto status and CAS are enforced again in the mutation transaction.

AuthenticationResponse.ownership carries the exact accepted OwnerState so an
agent or browser can establish offline trust without another hosted lookup.

## Owner transition lifecycle

OwnerAuthorizationService is hosted, except the local account-claim ceremony and
ObserveOwnership (which can also expose the device's independently verified pin).
SubmitOwnerTransition durably returns a versioned OwnerTransitionRecord. Retrying
that operation returns its original receipt; it never commits the proposal.
CompleteOwnerTransition takes a new operation ID, exact transition reference and
version, and a SignedRecord in `heddle.owner-transition-possession.v2`. Its canonical
bytes use `identity_management::recovery_action`; the key is the proposed authority
for rotation/recovery and the current authority for a policy change. Completion
returns AuthenticationResponse with the independently verifiable current ownership;
recovery also returns the newly enrolled client-owned credential result.
VetoOwnerTransition uses `heddle.owner-transition-veto.v2`, the same canonical action
including the expected version, and the current owner's signature. These proof
domains are distinct from Identity recovery proofs and cannot be substituted.
Pending OwnerState projections expose the same versioned record, original signed
transition, start and eligibility timestamps, and completion requirements.
