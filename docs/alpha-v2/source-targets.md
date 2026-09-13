# Shared source target observations

A signed anchor retains the revision, file, symbol and lines its author saw.
Following a rename or edit never rewrites that evidence or changes its signature.
`SourceTargetReference` identifies the shared target and selects its binding:
the viewed Thread, a named Thread, or an exact pinned revision.

Thread, Spool and collaboration observations carry `SourceTargetResolutionEvent`
alongside the records that refer to it. Clients maintain one resolution map per
endpoint and observation, shared by discussion anchors and annotation tags.
The key contains the reference and, only for a viewed-Thread binding, that actual
Thread. The current revision is a value, so a capture replaces one map entry
without rewriting every referring record. Historical Thread views resolve
against their selected revision; named bindings follow their named Thread and
pinned bindings retain the requested revision.

An upsert reports resolved, ambiguous, deleted or unavailable. Only resolved
includes an exact `SourceLocation`. Ambiguous and deleted can identify the
revision checked only after that revision passes independent visibility checks.
Unavailable has neither current coordinates nor a computed revision: missing
material and inaccessible material produce the same projection. An event never
grants access to the original or current source. Both original signed evidence
and emitted current locations must pass the relevant resource and visibility
gates before their identifiers leave the endpoint.

Snapshot frames carry only upserts. Live upserts and removals use the matching
stream data kind. They stage and commit at the same checkpoint as referring
records, and count against the same item and byte budgets. Emit at most one
upsert per key in a checkpoint batch. A live removal evicts only that map entry;
it does not delete the shared target or its authored records. Removing the last
referrer also removes its resolution from the observed window. Losing authority
may instead reset the whole view.

A replacement snapshot clears the map. Thread `collaboration` section replacement
and Spool `context` section replacement clear their resolution maps together
with their records. Standalone collaboration observations replace the map with
their snapshot or apply explicit live removals. Keys are local to the endpoint
and query; clients must not reuse an admitted resolution across different
credentials, endpoints or historical views.

Resolution storage uses the existing immutable target/file cores and signed
capture maps. Point reads walk the two target/file trie routes. Full closure
enumeration belongs to transfer verification and rebuilds, not each anchor read.
Query indexes may join the shared current binding, but must apply effective
record-and-referent visibility before pagination. Hidden candidates must not
change page counts, continuation presence or coverage. A differential guard must
keep that projection equal to the live source gate.
