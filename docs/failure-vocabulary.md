# Failure vocabulary

The hosted failure surface is one structured channel: a failed call carries
`CallFailure { code, message, error }`, and `CallFailure.error` is a single
[`ErrorDetail`](../proto/heddle/api/v1alpha1/errors.proto) whose `context` oneof
names what kind of failure it is and what to do about it. The authoritative
shapes live in `errors.proto`; this page records the semantics consumers must
agree on, especially for details a reader does not recognize.

## Vocabulary

| `ErrorDetail.context` arm | Meaning | Typical `ErrorReason` |
| --- | --- | --- |
| `retry` (10) | Resumable after the advised delay (`RetryAdvice.retry_after`) | `RATE_LIMITED`, `TRANSIENT` |
| `conflict` (11) | Compare-and-swap miss with expected/actual versions | `VERSION_CONFLICT`, `OPERATION_ID_REUSED`, `ALREADY_EXISTS` |
| `cursor` (12) | Pagination/stream cursor is stale/expired; restart from `restart_cursor` | `CURSOR_INVALID` |
| `capability` (13) | Caller lacks required capabilities | scope-driven |
| `policy` (14) | A named policy denied the request | `POLICY_DENIED` |
| `human_verification` (15) | A challenge the caller must satisfy | challenge-driven |
| `stream` (18) | Terminal streaming-RPC failure (`StreamFailure`) | status-driven |
| `unknown` (19) | A context arm from a newer contract version, preserved losslessly | `UNSPECIFIED` |

Field numbers 16 and 17 are consumed by the published release line and are not
available in this package.

## Stream failures and resume hints

`StreamFailure { code, message, error }` marks a mid-stream abort as a
stream-level failure to restart, not a per-item error. Its `code`/`message`
repeat the terminal transport outcome so the pair survives inside the single
structured channel.

Resume hints stay on `ErrorDetail`'s top-level `retry`/`cursor` arms — they
apply to the stream as a whole, not to the failure body. Because `context` is a
oneof, a hint rides **inside** the stream arm via `StreamFailure.error`: an
`ErrorDetail` whose context is `stream` nests its hint as
`StreamFailure.error.context = retry` or `= cursor`. Readers that only know the
top-level arms still find the hint by descending into the stream body; readers
that ignore `stream` lose nothing they could read before the field existed.

## Unknown-detail round-trip semantics

Forward compatibility of the vocabulary depends on how bindings treat fields
they did not compile in:

* **On the wire**, protobuf never loses data: an unrecognized `context` arm is
  preserved with its field number and bytes.
* **In generated bindings** (prost, and most proto runtimes), decoding drops
  undeclared oneof arms — prost does not retain unknown fields by default. An
  older client that decodes and re-encodes an `ErrorDetail` would silently
  collapse a newer server's detail to prose. That loss on the first hop is the
  failure mode the explicit arm exists to prevent.
* **The escape hatch**: a reader that decodes an `ErrorDetail` whose context
  arm is outside its compiled vocabulary MUST re-emit it as
  `context = unknown(UnknownDetail { type_url, value })`:
  * `type_url` follows the Any convention,
    `type.googleapis.com/heddle.api.v1alpha1.<MessageName>`.
  * `value` is the unrecognized message's encoded bytes, verbatim — not the
    whole enclosing `ErrorDetail`.

A reader that DOES know the type decodes `value` and may re-emit the typed arm
toward newer consumers. The field is pass-through only: servers never originate
`unknown`, and clients never invent semantics for a type they do not recognize.
This keeps a detail intact across any number of intermediate hops running older
vocabularies.

Executable form: `tests/error_vocabulary_contract.rs` round-trips the `stream`
and `unknown` arms through encode/decode and asserts the opaque payload bytes
decode back into the original typed message.
