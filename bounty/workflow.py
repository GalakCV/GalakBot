"""Manifest loading and dependency planning; no attack methodology lives here."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

from .core import Refused

TIERS = {"passive", "active-safe", "active-intrusive"}


def inside(root, path):
    root = Path(root).resolve()
    path = Path(path).resolve()
    if not path.is_relative_to(root):
        raise Refused("Path escapes its allowed directory")
    return path


class Skill:
    def __init__(self, root, name):
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name) or name == "code-audit":
            raise Refused("Only external-surface skills are supported")
        self.root = inside(root, Path(root) / name)
        self.name = name
        for filename in ("SKILL.md", "safety.md", "skill.yaml"):
            if not (self.root / filename).is_file():
                raise Refused(f"Missing skill file: {name}/{filename}")
        self.data = yaml.safe_load((self.root / "skill.yaml").read_text(encoding="utf-8"))
        if not isinstance(self.data, dict) or self.data.get("name") != name:
            raise Refused("Invalid skill manifest")
        self.phases = {}
        for item in self.data.get("phases", []):
            phase = dict(item)
            ident = phase.get("id", "")
            if not re.fullmatch(r"[a-z][a-z0-9-]*", ident) or ident in self.phases:
                raise Refused("Invalid or duplicate phase ID")
            phase["tier"] = phase.get("tier", self.data.get("default_tier"))
            if phase["tier"] not in TIERS:
                raise Refused("Unknown phase tier")
            phase["requires_authorization"] = bool(phase.get("requires_authorization") or
                                                      self.data.get("requires_authorization"))
            for key in ("run", "script", "helper", "miner", "runbook", "payloads"):
                if key in phase:
                    values = phase[key] if isinstance(phase[key], list) else [phase[key]]
                    for value in values:
                        if not isinstance(value, str) or not inside(self.root, self.root / value).is_file():
                            raise Refused(f"Missing/unsafe {key} in {ident}")
            self.phases[ident] = phase
        self.plan()  # Detect cycles and unknown dependencies before execution.

    def plan(self, selected=None, dependencies=True):
        result, visiting, done = [], set(), set()

        def visit(ident):
            if ident in done:
                return
            if ident in visiting or ident not in self.phases:
                raise Refused("Cyclic or unknown phase dependency: " + ident)
            visiting.add(ident)
            phase = self.phases[ident]
            if dependencies:
                for need in phase.get("needs", []):
                    visit(need)
            visiting.remove(ident)
            done.add(ident)
            result.append(phase)

        for ident in selected or self.phases:
            visit(ident)
        return result

    def digest(self):
        hashes = [(str(p.relative_to(self.root)), hashlib.sha256(p.read_bytes()).hexdigest())
                  for p in sorted(self.root.rglob("*")) if p.is_file() and "__pycache__" not in p.parts]
        return hashlib.sha256(json.dumps(hashes).encode()).hexdigest()
