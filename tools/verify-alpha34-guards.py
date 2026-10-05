"""Temporarily revert Rust reference/role guards; require red and restored green."""
from pathlib import Path
import os
import re
import subprocess
import sys

folder = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/api-alpha34-rust-guards')
folder.mkdir(parents=True, exist_ok=True)
helper = 'src/foreign_dependencies.rs'
model = 'tools/hybrid-native/src/foreign.rs'
text = Path(model).read_text()
start = text.index('        for reference in references {')
end = text.index('        let job_key', start)
binding = '''if installed
                        .job
                        .as_ref()
                        .is_none_or(|job| job.as_slice() != source.publisher)'''
cases = [
    ('native_support','src/native_witness.rs','foreign.require(original)?;','return Err(Reject::Scope);',False),
    ('import_support','src/import_authority.rs','foreign.require(original)?;','return Err(Reject::Scope);',False),
    ('bound',helper,'entries.len() > 128','false',False),
    ('sort',helper,'i > 0 && entries[i - 1].signed_native_digest >= entry.signed_native_digest','false',False),
    ('origin',helper,'entry.origin == carrier','false',False),
    ('thread',helper,' && entry.thread_genesis_digest == thread','',False),
    ('digest',helper,'entry.signed_native_digest == digest && ','',False),
    ('unused',helper,'self.used.iter().any(|used| !used)','false',False),
    ('version',helper,'entry.format_version != 1','false',False),
    ('unknown_origin',helper,'![1, 2].contains(&entry.origin)','false',False),
    ('width',helper,'width(&entry.signed_native_digest, 32)?;','',False),
    ('local_import_binding',model,binding,'if false',True),
    ('job_landing_role',model,'*request_key == job_key','false',True),
    ('missing_stage',model,text[start:end],'',True),
]

def run(name, phase, staged):
    if staged:
        command = ['cargo','test','--locked','--manifest-path','tools/hybrid-native/Cargo.toml','staged_foreign','--','--nocapture']
    else:
        command = ['cargo','test','--all-features','--test','foreign_dependencies_contract','--','--nocapture']
    result = subprocess.run(command, env=os.environ, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (folder / f'{name}-{phase}.log').write_text(result.stdout)
    if phase == 'red' and 'test result: FAILED' not in result.stdout:
        raise RuntimeError(f'{name}: no failing test; inspect log')
    if phase == 'green' and not re.search(r'test result: ok\. [1-9]\d* passed;',result.stdout):
        raise RuntimeError(f'{name}: no passing test; inspect log')
    return result.returncode

if len(sys.argv) > 2:
    selected = set(sys.argv[2].split(','))
    cases = [case for case in cases if case[0] in selected]
    if not cases or {case[0] for case in cases} != selected:
        raise RuntimeError('unknown probe selection')

for name, filename, before, after, staged in cases:
    path = Path(filename)
    original = path.read_text()
    try:
        if before not in original:
            raise RuntimeError(f'{name}: mutation site missing')
        path.write_text(original.replace(before,after))
        red = run(name,'red',staged)
        path.write_text(original)
        green = run(name,'green',staged)
        print(f'alpha.34 {name}: broken exit {red}; restored exit {green}',flush=True)
        if red != 101 or green != 0:
            raise RuntimeError(f'{name}: mutation not demonstrated')
    finally:
        path.write_text(original)
