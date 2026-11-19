"""Network compatibility layer for pinned upstream Python scripts.

Live workers additionally run in a network namespace. This is API routing, not
the OS security boundary. Raw sockets are unavailable inside the live sandbox.
"""
import io
import json
import os
from pathlib import Path
import runpy
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid


def request(tool, args):
    spool = Path(os.environ["BOUNTY_SPOOL"])
    ident = uuid.uuid4().hex
    temp = spool / (ident + ".tmp")
    temp.write_text(json.dumps(dict(tool=tool, args=args)), encoding="utf-8")
    temp.rename(spool / (ident + ".request"))
    result = spool / (ident + ".response")
    end = time.monotonic() + 900
    while not result.exists():
        if time.monotonic() > end:
            raise TimeoutError("Broker did not respond")
        time.sleep(0.03)
    data = json.loads(result.read_text())
    if data.get("code"):
        raise OSError(data.get("stderr", "Broker refused request"))
    return json.loads(data["stdout"])


class Response(io.BytesIO):
    def __init__(self, data):
        super().__init__(data.get("body", "").encode())
        self.headers = data.get("headers", {})
        self.status = self.code = data["status"]


def urlopen(req, *args, **kwargs):
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    if isinstance(req, urllib.request.Request) and (req.get_method() != "GET" or req.data):
        raise OSError("Only read-only GET requests allowed")
    data = request("http-read", [url])
    response = Response(data)
    if data["status"] >= 400:
        raise urllib.error.HTTPError(url, data["status"], "HTTP error", response.headers, response)
    return response


def gethostbyname_ex(host):
    data = request("dns-read", [host])
    if not data["addresses"]:
        raise socket.gaierror("No observed addresses")
    return host, data.get("aliases", []), data["addresses"]


def getaddrinfo(host, port, *args, **kwargs):
    _, _, addresses = gethostbyname_ex(host)
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port or 0)) for a in addresses]


def main():
    urllib.request.urlopen = urlopen
    socket.gethostbyname_ex = gethostbyname_ex
    socket.gethostbyname = lambda host: gethostbyname_ex(host)[2][0]
    socket.getaddrinfo = getaddrinfo
    def audit(event, args):
        if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "socket.gethostbyname"}:
            raise OSError("Direct networking is disabled; use broker APIs")
    sys.addaudithook(audit)
    sys.argv = sys.argv[1:]
    runpy.run_path(sys.argv[0], run_name="__main__")


if __name__ == "__main__":
    main()
