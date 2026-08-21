# Transactional stacked land

`WorkflowService.LandStack` accepts a set of thread members and has one durable
outcome: every member lands, or none does. The first weft implementation is
deliberately scoped to N threads in one spool. Cross-spool landing, including
coordination across separate spool audit chains, is a later capability; the
per-member `repo_path` keeps that extension additive.

## Follow-up weft handler

The handler should resolve every `(repo_path, thread, thread_id)` member and
reject stale `source_state` values before mutation. Within one spool transaction,
it should consult the existing merge gate through `weft-registry
access_merge_gate` (surfaced today by `native_check_merge_eligibility`) once per
member. It must read that gate, not reproduce its rules. The stack is eligible
only when every member's returned `unmet` list is empty, so new requirements such
as unresolved discussions from weft#1738 compose without another land-contract
change.

The handler should derive edges from `ThreadSummary.parent_thread`, topo-sort the
set itself, and apply members bottom-up. Request order has no meaning. Any gate
failure aborts before commit; any apply failure rolls back the spool transaction,
including earlier attempted applies. The response reports `ROLLED_BACK`,
`landed = false` for every member, and the per-member gate output or apply failure
that caused the abort. Only an atomic commit returns `COMMITTED` with every
member's `landed = true`.
