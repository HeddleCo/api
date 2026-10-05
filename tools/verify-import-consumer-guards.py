# Checked-in Rust half of the alpha.32 consumer guard evidence. Restores source bytes.
from pathlib import Path
import subprocess
path=Path('src/import_authority.rs');original=path.read_text();out=Path('/tmp/api352-rust-guards');out.mkdir(exist_ok=True)
cases=[
 ('caller_owner','alpha32_caller_availability_vectors','if retained.connection.is_some()\n        && caller.connection_owner_account != Some(caller.caller_account)','if false'),
 ('required_controls','alpha32_controls_reject_then_pass','validate_retry_state_response(request, response)?;\n    let controls','validate_retry_state_response(request, response)?; if true { return Ok(()); }\n    let controls'),
 ('recovery_noop','alpha32_recovery_snapshot_vectors','if witnessed_prefix > 0 || new_set {','if true {'),
 ('recovery_history','alpha32_recovery_snapshot_vectors','accepted_history: if witnessed_prefix > 0 {','accepted_history: if true {'),
 ('receipt_times','alpha32_owner_times_are_internal_and_receipt_ordered','let time = times[i].map(|(_, time)| time);','let time = times[i].map(|_| 900);'),
]
def run(name,stage,pattern):
 r=subprocess.run(['cargo','test','--all-features','--test','import_consumer_contract',pattern,'--','--nocapture'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 (out/(name+'-'+stage+'.log')).write_text(r.stdout);return r.returncode
try:
 for name,pattern,before,after in cases:
  assert before in original,'missing mutation: '+before
  path.write_text(original.replace(before,after,1));red=run(name,'red',pattern)
  path.write_text(original);green=run(name,'green',pattern)
  print(f'{name}: disabled guard exit {red}; restored guard exit {green}',flush=True)
  assert red==101 and green==0,(name,red,green)
finally:path.write_text(original)
