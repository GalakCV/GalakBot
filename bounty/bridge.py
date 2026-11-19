"""CLI shim inside the isolated worker. The parent owns all network tools."""
import json
import os
from pathlib import Path
import sys
import time
import uuid


def main():
    spool = Path(os.environ["BOUNTY_SPOOL"])
    ident = uuid.uuid4().hex
    tool = sys.argv[1]
    args = sys.argv[2:]
    stdin = ""
    if tool in {"gau", "waybackurls", "openssl"} or (tool == "dnsx" and "-l" not in args):
        stdin = sys.stdin.read(1048576)
    data = dict(tool=tool, args=args, stdin=stdin)
    tmp = spool / (ident + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.rename(spool / (ident + ".request"))
    response = spool / (ident + ".response")
    deadline = time.monotonic() + 900
    while not response.exists():
        if time.monotonic() > deadline:
            raise SystemExit(124)
        time.sleep(0.03)
    result = json.loads(response.read_text(encoding="utf-8"))
    sys.stdout.write(result.get("stdout", ""))
    sys.stderr.write(result.get("stderr", ""))
    raise SystemExit(result.get("code", 1))


if __name__ == "__main__":
    main()
