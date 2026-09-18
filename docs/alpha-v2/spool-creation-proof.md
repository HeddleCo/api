# Private authorization and portable Spool creation

Status: proposed replacement for the draft delegated creation proof. The current
`SpoolCreationProof.sealed_biscuit` implementation must be replaced before the
delegated creation flow is exposed in Tapestry. This document is not evidence that
the replacement verifier or credential producers have shipped.

## Two independent decisions

A portable owner genesis establishes which account authority a creator's signing
key descends from and binds that creator's signature to one new Spool UUID. It
does not prove permission to create under a particular hosted parent.

Fresh `CreateSpool` admission already has a private ordinary Biscuit, the caller's
request proof, the exact request body, the current account owner state, and the
current parent ACL. Those inputs decide whether this caller can create this Spool
here, now. The signed request body binds the parent, slug, settings and public
genesis. Repeating that authorization credential in the owner genesis adds no
necessary admission boundary.

Sealing a Biscuit removes its attenuation secret; it does not redact its facts
or ancestor blocks. The current proof therefore publishes unrelated private
resource paths and identity/session/delegation metadata when owner genesis is
included in Spool observations or source fetches. The creator statement also
unnecessarily persists the initial parent path and name in this portable record.

## Public evidence

Keep the existing immutable `SpoolOwnerGenesis` and direct owner-signature path.
For delegated creation, replace the embedded Biscuit with public signing-key
association evidence:

- The complete signed owner history authenticates the exact owner state that
  existed at creation. Fresh admission compares it with the actual current state.
- An optional existing `SignedMintRootAttachment` associates a device's mint key
  with that exact owner state. Without it, the chain starts at the current owner
  authority key.
- A bounded ordered chain of public signing-key delegation certificates extends
  that association to the creator's proof key. Each issuer signs the next key,
  exact account and owner-state binding, previous certificate digest, validity
  interval, and nonce. The first parent digest binds the mint-root attachment,
  or is empty only when the issuer is the owner authority itself.
- The creator signs the exact genesis digest, account, owner state and sequence,
  creator key and claimed creation time. This statement contains no parent UUID,
  parent path, slug, credential, session ID or ordinary capability facts.

Signing-key certificates attest key association only. They carry no `read`,
`write`, `admin`, `CreateSpool` or owner-only grants. A descendant cannot extend
its parent's validity interval, change the owner state, replace a parent link or
skip an issuer signature. Ordinary Biscuit attenuation remains the sole source
of delegated resource permission. This separation also preserves the narrow
owner-only purge/rotation/recovery model.

Use a distinct canonical signature domain for signing-key delegation. Never
reinterpret a request-PoP signature, a Biscuit block signature, a passkey
assertion, a root-attachment possession proof, or an existing `pop_delegation`
fact as this public certificate. Those signatures authenticate different
statements. An arbitrary existing Biscuit cannot be losslessly projected into
public association evidence without the relevant issuer signatures.

## Fresh admission

The endpoint must perform all of these checks against its current state:

1. Verify the ordinary request credential and its proof key, inherited method
   and resource restrictions, expiry, account binding and current revocations.
2. Check the actual parent's administrative permission and child-creation
   policy. The caller may be a human or a fully delegated agent.
3. Verify the public owner genesis and signing-key association chain. Require
   the creator key to equal the authenticated request proof key and the owner
   account to equal the account established by the credential.
4. Require the current owner authority and sequence for a new Spool. Verify
   current certificate intervals and applicable key revocations. A creator's
   claimed old timestamp is never evidence of prior admission.
5. Atomically create the resource, original public genesis and operation receipt
   under the existing idempotency and authorization-epoch fences.

Do not introduce a second private creation credential. The actual signed RPC's
Biscuit is the private admission credential. A private audit store may retain
the existing admission digest and revocation identifiers where needed; public
observations and source transfers must not carry the token itself.

Historical verification checks signatures, owner-history continuity and exact
genesis attribution. It does not reevaluate today's ACL against yesterday's
creation, and certificate expiry does not erase an already created Spool.
Structural verification is never a fresh admission receipt.

## Credential producers

Certificate issuance must accompany ordinary credential delegation:

- A browser with the actual current owner signing key can sign a direct
  association. A passkey assertion alone cannot substitute for that signature.
- A device with an existing public association chain signs the next link while
  attenuating its existing Biscuit to the new agent/device proof key.
- Pairing returns the public association chain alongside the privately handed
  off Biscuit. The user remains the authority; no Weft signing key participates
  for self-rooted accounts.
- Server-rooted accounts retain their explicit per-user custody path. Deferred
  human accounts retain the current signed claim/rotation model.
- Credential persistence stores and transports the public chain with the exact
  proof-key credential. Account replacement must discard an in-progress creation
  prepared with the old identity.

This is a clean contract cutover. Do not keep a sealed-Biscuit fallback for
credentials that lack public association evidence. Such credentials need a new
association from their issuer before delegated creation; ordinary operations
continue to be governed by their valid private Biscuit.

## Required evidence before enabling the flow

Exercise actual browser/agent producers and endpoint admission, not manually
assembled certificates alone. Prove nested delegation, current-key rotation,
per-user custody and offline device verification. Reject modified genesis,
cross-account chains, substituted proof keys, missing/reordered issuer links,
expired fresh creation, retired owner states, and method/resource-attenuated
or revoked private credentials. A read-only agent may hold a valid public key
association and must still be unable to create a hosted Spool.

Publish with credentials containing recognizable unrelated private facts and
assert those facts, the original credential bytes, private parent path and
initial name are absent from every portable genesis, Spool observation and
FetchContent artifact. Keep public evidence verification usable without an
ordinary Biscuit parser where the remaining owner-only capability format allows
that dependency separation.
