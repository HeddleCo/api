"""Mutate ONE Rust guard at a time; require test failures and restored passes."""
from pathlib import Path
import os
import re
import subprocess
import sys

path = Path('src/import_authority.rs')
original = path.read_text()
directory = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/api-alpha33-rust-guards')
directory.mkdir(parents=True, exist_ok=True)
pair_start = original.index('    validity(', original.index('pub fn check_import_genesis_publication_pair'))
pair_end = original.index('    if admission.purpose', pair_start)
cases = [
    ('p1_window', 'alpha33_direct_p1_pair', original[pair_start:pair_end], ''),
    ('p1_p3_time', 'alpha33_p1_window', '|| admission.observed_at_unix_millis != publication.observed_at_unix_millis', ''),
    ('p1_p3_transaction', 'alpha33_p1_window', '|| admission.host_transaction_id != publication.host_transaction_id', ''),
    ('p1_p3_order', 'alpha33_p1_window', '|| admission.admission_order >= publication.admission_order', ''),
    ('p1_p3_executor', 'alpha33_p1_window', '|| admission.executor_id != publication.executor_id', ''),
    ('duplicate_p1', 'alpha33_p1_window', '!admitted_geneses.insert(genesis.clone())', 'false'),
    ('duplicate_p3', 'alpha33_p1_window', 'matches.len() != 1', 'matches.is_empty()'),
    ('unconsumed_p3', 'alpha33_p1_window', 's.purpose == 3 && !selected_publications.contains(&signed)', 'false'),
    ('signed_window_ceiling', 'alpha33_window_ceiling', '> i128::from(MAX_DELEGATION_WINDOW_SECONDS)', '> i128::MAX'),
    ('host_window_ceiling', 'alpha33_window_ceiling', 'prepared.max_validity_duration_seconds > MAX_DELEGATION_WINDOW_SECONDS', 'false'),
    ('window_24h', 'alpha33_24h', 'end - start > i128::from(prepared.max_validity_duration_seconds)', 'end - start > 3600'),
    ('host_budget_bytes', 'alpha33_direct_publication_budget', 'o.result_bytes > remaining.max_result_bytes', 'false'),
    ('retry_status_reason', 'alpha33_status_retry', '''!matches!(
                (response.status, *reason),
                (1, 1 | 2 | 6) | (2, 3) | (3, 4) | (4, 5) | (5, 7)
            )''', '!(1..=7).contains(reason)'),
    ('hostile_body', 'alpha33_hostile_missing', 'if operation.body.is_none()', 'if false'),
    ('commit_conflict_wire', 'alpha33_commit_conflict_wire', 'ErrorReason::ImportDestinationConflict', 'ErrorReason::AlreadyExists'),
    ('sibling_full_ref', 'alpha33_direct_sibling_ref', 'held.ref_name == selected.ref_name', 'false'),
    ('sibling_target', 'review_fix_reservation', 'held.target_thread_id == selected.target_thread_id', 'false'),
    ('sibling_genesis', 'review_fix_reservation', 'held.genesis_digest == selected.genesis_digest', 'false'),
]


def run(name, stage, pattern):
    suite = 'import_sibling_jobs_contract' if name.startswith('sibling_') else 'import_authority_witness_contract'
    result = subprocess.run(['cargo', 'test', '--all-features', '--test', suite, pattern, '--', '--nocapture'],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=os.environ)
    (directory / f'{name}-{stage}.log').write_text(result.stdout)
    if stage == 'red' and 'test result: FAILED' not in result.stdout:
        raise RuntimeError(f'{name}: not a test failure; see log')
    if stage == 'green' and not re.search(r'test result: ok\. [1-9]\d* passed;', result.stdout):
        raise RuntimeError(f'{name}: no passing test executed')
    return result.returncode


try:
    for name, pattern, before, after in cases:
        if before not in original:
            raise RuntimeError('missing mutation ' + before)
        path.write_text(original.replace(before, after, 1))
        red = run(name, 'red', pattern)
        path.write_text(original)
        green = run(name, 'green', pattern)
        print(f'{name}: broken exit {red}; restored exit {green}', flush=True)
        if red != 101 or green != 0:
            raise RuntimeError(f'{name}: guard not demonstrated')
finally:
    path.write_text(original)
