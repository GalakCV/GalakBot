"""Read-only runtime mounts for system Python, venvs and hosted toolchains."""
from pathlib import Path
import sys


def runtime_mounts():
    paths = []
    for value in ("/usr", "/bin", "/lib", "/lib64", sys.base_prefix, sys.prefix):
        path = Path(value)
        if path.exists() and not any(path == previous or path.is_relative_to(previous) for previous in paths):
            paths.append(path)
    return [argument for path in paths for argument in ("--ro-bind", str(path), str(path))]
