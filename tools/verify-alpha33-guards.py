"""Exercise Rust guard regressions, restoring exact source even on failure."""
from pathlib import Path
import os, subprocess, re, sys
path=Path('src/import_authority.rs'); original=path.read_text()
directory=Path(sys.argv[1] if len(sys.argv)>1 else '/tmp/api-alpha33-rust-guards');directory.mkdir(parents=True,exist_ok=True)
start=original.index('                verify_delegation(',original.index('            1 => {',original.index('pub fn verify_import_bundle_witnesses')))
end=original.index('                let payload',start)
p1=original[start:end]
ordering='''if s.observed_at_unix_millis != publication.observed_at_unix_millis
                    || s.host_transaction_id != publication.host_transaction_id
                    || s.admission_order >= publication.admission_order'''
conflict='''reservation.branches.iter().any(|held| {
                    held.ref_name == selected.ref_name
                        || held.target_thread_id == selected.target_thread_id
                        || held.genesis_digest == selected.genesis_digest
                })'''
cases=[
 ('p1_window','import_authority_witness_contract','alpha33_p1_window',[(p1,'')]),
 ('p1_p3_order','import_authority_witness_contract','alpha33_p1_window',[(ordering,'if false')]),
 ('window_24h','import_authority_witness_contract','alpha33_24h', [('|| end - start > i128::from(prepared.max_validity_duration_seconds)','|| end - start > i128::from(prepared.max_validity_duration_seconds) || end - start > 3600')]),
 ('duplicate_sibling_commit','import_sibling_jobs_contract','alpha33_duplicate_sibling',[(conflict,'false')]),
 ('cumulative_2x','import_authority_witness_contract','alpha33_cumulative',[
  ('total_bytes > original_scope.max_result_bytes','false'),('*bytes > scope.max_result_bytes','false'),
  ('check_import_publication_budget(operation, delegation, &before)?;',''),
  ('check_import_publication_budget(o, delegation, &committed_before)?;',''),
 ]),
]
def run(name,stage,suite,pattern):
 r=subprocess.run(['cargo','test','--all-features','--test',suite,pattern,'--','--nocapture'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=os.environ)
 (directory/f'{name}-{stage}.log').write_text(r.stdout)
 if stage=='red' and 'test result: FAILED' not in r.stdout:raise RuntimeError(f'{name}: failure was not a test failure')
 if stage=='green' and not re.search(r'test result: ok\. [1-9]\d* passed;',r.stdout):raise RuntimeError(f'{name}: no passing test executed')
 return r.returncode
try:
 for name,suite,pattern,changes in cases:
  mutated=original
  for before,after in changes:
   if before not in mutated:raise RuntimeError('missing mutation '+before)
   mutated=mutated.replace(before,after,1)
  path.write_text(mutated);red=run(name,'red',suite,pattern)
  path.write_text(original);green=run(name,'green',suite,pattern)
  print(f'{name}: broken exit {red}; restored exit {green}',flush=True)
  if red!=101 or green!=0:raise RuntimeError(f'{name}: guard not demonstrated')
finally:path.write_text(original)
