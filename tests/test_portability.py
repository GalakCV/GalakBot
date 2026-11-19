import hashlib
import json
from pathlib import Path
import subprocess
import uuid

import pytest

from bounty.core import Refused
from bounty.executor import bash_path
from bounty.portability import normalized_bytes, normalized_hash, prepare_skill


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def workspace():
    path = ROOT / ".test-runs" / ("portability-" + uuid.uuid4().hex)
    path.mkdir(parents=True)
    return path


def test_hash_is_identical_for_lf_crlf_and_old_mac(workspace):
    source = workspace / "script.py"
    versions = [b"print('test')\nprint('done')\n", b"print('test')\r\nprint('done')\r\n", b"print('test')\rprint('done')\r"]
    observed = []
    for data in versions:
        source.write_bytes(data)
        observed.append(normalized_hash(source))
    assert len(set(observed)) == 1
    assert observed[0] == hashlib.sha256(versions[0]).hexdigest()


def test_snapshot_preserves_relative_files_and_normalizes_before_execution(workspace):
    skill = workspace / "source" / "custom"
    (skill / "scripts").mkdir(parents=True)
    (skill / "payloads").mkdir()
    script = skill / "scripts" / "run.sh"
    script.write_bytes(b'#!/usr/bin/env bash\r\nHERE="$(cd "$(dirname "$0")" && pwd)"\r\ncat "$HERE/../payloads/message.txt"\r\n')
    (skill / "payloads/message.txt").write_bytes(b"fixture only\r\n")
    recon = skill.parent / "recon/scripts"
    recon.mkdir(parents=True)
    (recon / "scope_filter.py").write_bytes(b"# shared guard\r\n")
    copied = prepare_skill(skill, workspace / "run/work/prepared")
    assert b"\r" not in (copied / "scripts/run.sh").read_bytes()
    assert b"\r" in script.read_bytes(), "operator checkout must remain untouched"
    assert (copied.parent / "recon/scripts/scope_filter.py").read_bytes() == b"# shared guard\n"
    assert bash_path(), "fixture execution requires Bash"
    result = subprocess.run([bash_path(), str(copied / "scripts/run.sh").replace("\\", "/")],
                            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "fixture only\n"


def test_all_reviewed_pins_use_normalized_bytes():
    skills = ROOT / ".external/G-Skills"
    pins = json.loads((ROOT / "bounty/trusted.json").read_text())
    assert pins
    for relative, expected in pins.items():
        data = (skills / relative).read_bytes()
        assert normalized_hash(skills / relative) == expected
        assert hashlib.sha256(normalized_bytes(normalized_bytes(data).replace(b"\n", b"\r\n"))).hexdigest() == expected


def test_snapshot_refuses_source_as_destination(workspace):
    source = workspace / "skill"
    source.mkdir()
    with pytest.raises(Refused, match="destination"):
        prepare_skill(source, source / "nested")
