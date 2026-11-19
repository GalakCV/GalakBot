"""Agent calls use the same no-network process/broker boundary as skill scripts."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid

from .core import Refused, write_json
from .policy import InvalidArguments, validate_request


def dispatch(layer, request, agent_id):
    try:
        request = validate_request(layer, request)
    except InvalidArguments as error:
        layer.breaker.invalid(str(error))
        raise
    work = layer.ctx.root / "work/agents" / agent_id / uuid.uuid4().hex
    spool = work / "spool"
    spool.mkdir(parents=True)
    bridge = Path(__file__).with_name("bridge.py").resolve()
    env = layer.clean_env()
    env.update(BOUNTY_SPOOL=str(spool), PYTHONDONTWRITEBYTECODE="1")
    if os.name == "nt":
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    command = [sys.executable, str(bridge), request["tool"], *request["args"]]
    if layer.fixture is None:
        if sys.platform != "linux" or not shutil.which("bwrap"):
            raise Refused("Agent tools require Linux bubblewrap; no unsafe fallback")
        from .runtime import runtime_mounts
        mounts = runtime_mounts()
        command = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", *mounts,
                   "--proc", "/proc", "--dev", "/dev", "--ro-bind", str(bridge.parent), str(bridge.parent),
                   "--bind", str(layer.ctx.root), str(layer.ctx.root), "--chdir", str(work), "--", *command]
    stdin_file = work / "stdin.txt"
    stdin_file.write_text(request.get("stdin", ""), encoding="utf-8")
    result = None
    with stdin_file.open("rb") as stdin, (work / "worker.log").open("wb") as log:
        process = subprocess.Popen(command, stdin=stdin, stdout=log, stderr=log, env=env, cwd=work,
                                   start_new_session=os.name != "nt")
        try:
            while process.poll() is None:
                layer.breaker.check()
                for path in spool.glob("*.request"):
                    body = json.loads(path.read_text())
                    # The bridge must not change the request authorized by the parent.
                    if body != {"tool": request["tool"], "args": request["args"], "stdin": request.get("stdin", "")}:
                        layer.breaker.trip("Worker request differs from authorized envelope")
                    result = layer.call(body)
                    write_json(path.with_suffix(".response"), result)
                    path.rename(path.with_suffix(".handled"))
                time.sleep(0.01)
            if result is None:
                layer.breaker.outcome(False)
                raise Refused("Sandbox worker returned no broker result")
        finally:
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
    layer.ctx.trace("sandbox.call", agent_id=agent_id, tool=request["tool"],
                    mode="fixture" if layer.fixture is not None else "bubblewrap", gates={"broker": True})
    return result
