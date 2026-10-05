"""Fail-then-pass review-fix guards. Run alone: temporarily mutates Rust source."""
from pathlib import Path
import subprocess
import sys
path = Path('src/import_authority.rs')
original = path.read_text()
out = Path(sys.argv[1] if len(sys.argv)>1 else '/tmp/api352-review-rust-guards')
out.mkdir(parents=True, exist_ok=True)
def original_gate(function):
    start=original.index('pub fn '+function)
    a=original.index('    check_original_import_window(',start)
    b=original.index(')?;',a)+3
    return original[a:b]
cases = [
 ('renew_certificate_remaining','import_authority_witness_contract','review_fix_renewal_narrowing', [('|| new_scope.max_result_bytes','|| false && new_scope.max_result_bytes')]),
 ('renew_permission_remaining','import_authority_witness_contract','review_fix_renewal_narrowing', [('|| scope.max_result_bytes','|| false && scope.max_result_bytes')]),
 ('publication_live','import_authority_witness_contract','review_fix_publication_budget', [('if remaining.max_operations == 0 || o.result_bytes > remaining.max_result_bytes {','if false {')]),
 ('publication_witness','import_authority_witness_contract','review_fix_publication_budget', [('check_import_publication_budget(operation, delegation, &before)?;','')]),
 ('owner_interval','import_authority_witness_contract','review_fix_owner_resolver', [('|| time.is_some_and(|t| {','|| false && time.is_some_and(|t| {')]),
 ('reservation_ownership','import_sibling_jobs_contract','review_fix_reservation_ownership', [('if activation && !owns_reservation {','if false && activation && !owns_reservation {')]),
 ('sibling_thread','import_sibling_jobs_contract','review_fix_reservation_ownership', [('|| held.target_thread_id == selected.target_thread_id','')]),
 ('sibling_genesis','import_sibling_jobs_contract','review_fix_reservation_ownership', [('|| held.genesis_digest == selected.genesis_digest','')]),
 ('scope_thread','import_sibling_jobs_contract','review_fix_reservation_ownership', [('other.target_thread_id == b.target_thread_id','false')]),
 ('scope_genesis','import_sibling_jobs_contract','review_fix_reservation_ownership', [('other.genesis_digest == b.genesis_digest','false')]),
 ('prepare_window','import_authority_witness_contract','review_fix_host_max_renewal', [('check_original_import_window(original_admission.ok_or(Reject::Canonical)?)?;','let _ = original_admission;')]),
 ('renew_window','import_authority_witness_contract','review_fix_renew_original_window', [(original_gate('validate_renew_request'),'')]),
 ('retry_window','import_job_control_contract','review_fix_retry_original_window', [(original_gate('check_retry_admission'),'')]),
 ('reservation_release','import_sibling_jobs_contract','review_fix_original_window_releases', [('r.spool_uuid != spool_uuid || r.logical_job_id != logical_job_id','true || r.spool_uuid != spool_uuid || r.logical_job_id != logical_job_id')]),
 ('prepare_max_retained','import_authority_witness_contract','review_fix_host_max_renewal', [('.max_result_bytes = u64::MAX;','.max_result_bytes = 1;')]),
 ('recovery_prefix','import_authority_witness_contract','review_fix_recovery_prefix', [('accepted_history: if witnessed_prefix > 0 {','accepted_history: if witnessed {')]),
 ('overflow_reason','import_authority_witness_contract','review_fix_overflow_reason', [('consumed = consumed\n                .checked_add(slot.result_bytes)\n                .ok_or(Reject::Bounds)?;','consumed = consumed\n                .checked_add(slot.result_bytes)\n                .ok_or(Reject::RenewalFork)?;')]),
]
# The new publication checks overlap bundle counters. Isolate the certificate
# counter by removing those equivalent checks; leave the original total intact.
cases.append(('narrowed_certificate','import_authority_witness_contract','review_fix_narrowed_bundle',[
 ('check_import_publication_budget(operation, delegation, &before)?;',''),
 ('check_import_publication_budget(o, delegation, &committed_before)?;',''),
 ('*bytes > scope.max_result_bytes','false'),
]))
# This test also checks live admission, whose guard is kept: only the bundle
# assertion changes. Parent total=1500, child=1000, publication sum=1200.
def run(name, stage, suite, pattern):
    r=subprocess.run(['cargo','test','--all-features','--test',suite,pattern,'--','--nocapture'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    (out/f'{name}-{stage}.log').write_text(r.stdout)
    return r.returncode
try:
    for name,suite,pattern,replacements in cases:
        if len(sys.argv)>2 and name != sys.argv[2]: continue
        mutant=original
        for before,after in replacements:
            if before not in mutant: raise RuntimeError('missing mutation: '+before)
            mutant=mutant.replace(before,after,1)
        path.write_text(mutant)
        red=run(name,'red',suite,pattern)
        path.write_text(original)
        green=run(name,'green',suite,pattern)
        print(f'{name}: disabled guard exit {red}; restored guard exit {green}',flush=True)
        if red != 101 or green != 0: raise RuntimeError((name,red,green))
        # A compiler error is never a guard demonstration.
        if 'test result: FAILED.' not in (out/f'{name}-red.log').read_text(): raise RuntimeError(name+': did not execute a failing test')
finally:
    path.write_text(original)
