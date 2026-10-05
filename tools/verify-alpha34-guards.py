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
start = text.index('        let (spool, authority) =')
end = text.index('        let owner = verify_owner_history', start)
def scope_guard(filename, marker):
    value = Path(filename).read_text()
    start = value.index('        if !', value.index(marker))
    end = value.index('        }', value.index('return Err(Reject::Scope);', start)) + len('        }')
    return value[start:end]
binding = '''if installed
                        .job
                        .as_ref()
                        .is_none_or(|job| job.as_slice() != source.publisher)'''
cases = [
    ('native_support','src/native_witness.rs','foreign.require(original)?;','return Err(Reject::Scope);',False),
    ('import_support','src/import_authority.rs','foreign.require(original)?;','return Err(Reject::Scope);',False),
    ('bound','src/native_witness.rs','b.encoded_len() > import::MAX_BUNDLE_BYTES','false',False),
    ('sort',helper,'i > 0 && entries[i - 1].signed_native_digest >= entry.signed_native_digest','false',False),
    ('origin',helper,'entry.origin == carrier as i32','false',False),
    ('thread',helper,' && entry.thread_genesis_digest == thread','',False),
    ('digest',helper,'entry.signed_native_digest == digest && ','',False),
    ('unused',helper,'self.used.iter().any(|used| !used)','false',False),
    ('version',helper,'entry.format_version != 1','false',False),
    ('unknown_origin',helper,'!matches!(\n                ForeignDependencyOrigin::try_from(entry.origin),\n                Ok(ForeignDependencyOrigin::Import | ForeignDependencyOrigin::Native)\n            )','false',False),
    ('width',helper,'width(&entry.signed_native_digest, 32)?;','',False),
    ('local_import_binding',model,binding,'if false',True),
    ('job_landing_role','src/native_witness.rs','import::verify_landing_key_roles(p, set.known_job_keys(), &[])?;','',False),
    ('missing_stage',model,text[start:end],'',True),
    ('native_p2_subject','src/native_witness.rs',scope_guard('src/native_witness.rs','let subject_thread ='),' ',False),
    ('import_p2_subject','src/import_authority.rs',scope_guard('src/import_authority.rs','let subject_thread ='),' ',False),
    ('import_execution','src/import_authority.rs',scope_guard('src/import_authority.rs','let thread = crate::foreign_dependencies::thread(execution)?;'),' ',False),
    ('import_genesis_identity','src/import_authority.rs','else if original.format == "heddle-thread-genesis-v1"','else if false && original.format == "heddle-thread-genesis-v1"',False),
    ('prefix_nonzero',helper,'entry.prefix_admission_order == 0','false',False),
    ('known_job_roles','src/import_authority.rs','known_job_keys.contains(key)','false',False),
    ('forbidden_landing_roles','src/import_authority.rs','forbidden_keys.contains(key)','false',False),
    ('import_delegation_job_role','src/import_authority.rs','verify_landing_key_roles(p, &job_keys, &[])?;','',False),
    ('prefix_extension',model,'            self.install_prefix(\n                f,\n                foreign["id"].as_str().context("prefix id")?,\n                catalog,\n                visiting,\n            )?;', '            return Err(codec::Reject::Scope.into());',True),
    ('prefix_binding',model,'|| installed.admission_order != reference.prefix_admission_order','',True),
    ('installed_spool',model,'|| installed.spool != spool','',True),
    ('installed_authority',model,'|| installed.authority != authority','',True),
    ('installed_bytes',model,'if referenced != &installed.record','if false',True),
    ('account_admission',model,'installed.admission_purpose != 2','false',True),
    ('integration_admission',model,'installed.admission_purpose != 4','false',True),
    ('original_cycle',model,'visiting.contains(&key)','false',True),
    ('import_selected_roles','src/import_authority.rs','verify_landing_key_roles(payload, &known, facts.forbidden_landing_keys)?;','',False),
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
