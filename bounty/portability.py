"""Portable script snapshots and hashes for reviewed, external skills.

Never rewrite the operator's checkout while preparing a run. Each worker gets
an LF-normalized snapshot below its own run directory instead.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .core import Refused


def normalized_bytes(data: bytes) -> bytes:
    """Canonicalize Windows/old-Mac line endings without decoding the file."""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def normalized_hash(path: Path) -> str:
    return hashlib.sha256(normalized_bytes(Path(path).read_bytes())).hexdigest()


def prepare_skill(skill_root: Path, destination_root: Path) -> Path:
    """Copy one skill and its shared recon guard into a worker-owned directory.

    Returns ``destination_root / skill_root.name``. All relative script,
    payload, runbook and sibling ``../recon`` references remain valid. Callers
    must place destination_root under their target's run directory, then use
    the returned root to construct the executable path. Symlinks are refused
    instead of following them into unrelated filesystem content.
    """
    original = Path(skill_root)
    if original.is_symlink():
        raise Refused("Skill snapshots cannot follow symlinks")
    source = original.resolve()
    destination = Path(destination_root).resolve()
    if destination == source or destination.is_relative_to(source):
        raise Refused("Skill snapshot destination must not be inside the source")
    roots = [source]
    recon = source.parent / "recon"
    if source.name != "recon" and recon.is_dir():
        roots.append(recon)
    for root in roots:
        if root.is_symlink():
            raise Refused("Skill snapshots cannot follow symlinks")
        copied_root = destination / root.name
        copied_root.mkdir(parents=True, exist_ok=False)
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if any(part in {".git", "__pycache__", ".pytest_cache"} for part in relative.parts):
                continue
            if path.is_symlink():
                raise Refused("Skill snapshots cannot follow symlinks")
            target = copied_root / relative
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                data = path.read_bytes()
                if path.suffix.lower() in {".sh", ".py", ".md", ".yaml", ".yml", ".txt"}:
                    data = normalized_bytes(data)
                target.write_bytes(data)
                target.chmod(0o755 if path.suffix.lower() in {".sh", ".py"} else 0o644)
    return destination / source.name
