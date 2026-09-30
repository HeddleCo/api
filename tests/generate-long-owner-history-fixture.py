"""Generate a verified format-3 bundle without modifying the Heddle checkout.

Usage: python3 tests/generate-long-owner-history-fixture.py /path/to/heddle
The pinned verifier checks the current issuer, every transition and the subject
Biscuit. Its timeline envelope still has the old cap, so generation calls the
underlying bundle verifier directly. API envelope validation is tested separately.
"""

import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parent.parent
REVISION = "b83f6e83c16cfb0b2f58f6f2b599c25bfe1a65be"
OUTPUT = ROOT / "tests/fixtures/timeline-owner-long-history.json"
WORK = ROOT / "build/long-owner-history-verifier"


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    archive = subprocess.check_output([
        "git", "-C", sys.argv[1], "archive", REVISION, "Cargo.toml", "Cargo.lock",
        "crates/capability-verifier", "crates/biscuit-verifier",
    ])
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(WORK, filter="data")
    manifest = WORK / "Cargo.toml"
    text = manifest.read_text()
    text = re.sub(r"(?ms)^members = \[.*?^\]", 'members = ["crates/capability-verifier", "crates/biscuit-verifier"]', text)
    text = re.sub(r"(?m)^default-members = .*\n", "", text)
    text = text.split("[patch.crates-io]")[0]
    text += f'\n[patch.crates-io]\nheddle-api = {{ path = {json.dumps(str(ROOT))} }}\n'
    manifest.write_text(text)
    version = json.loads((ROOT / "package.json").read_text())["version"]
    for crate in ["capability-verifier", "biscuit-verifier"]:
        manifest = WORK / f"crates/{crate}/Cargo.toml"
        manifest.write_text(manifest.read_text().replace("=0.31.0-alpha.10", f"={version}"))
    extension = (ROOT / "tests/fixtures/long-owner-history-generator.rs").read_text()
    tests = WORK / "crates/capability-verifier/src/timeline_tests.rs"
    tests.write_text(tests.read_text() + "\n" + extension)
    env = dict(os.environ, OWNER_HISTORY_OUTPUT=str(OUTPUT), TMPDIR="/home/scratch")
    subprocess.run([
        "cargo", "test", "--manifest-path", str(WORK / "Cargo.toml"),
        "-p", "heddleco-capability-verifier", "generate_api_long_owner_history", "--", "--nocapture",
    ], env=env, check=True)


if __name__ == "__main__":
    main()
