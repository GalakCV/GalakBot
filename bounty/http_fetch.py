"""Single bounded HTTP read. Parent enforces scope and a process-level deadline."""
import json
import sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 10
        user_agent = sys.argv[3] if len(sys.argv) > 3 else "BountyHarness/0.1"
        response = opener.open(Request(sys.argv[1], headers={"User-Agent": user_agent}), timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(65536).decode("utf-8", errors="replace")
        print(json.dumps(dict(status=response.code, headers=dict(response.headers), body=body)))


if __name__ == "__main__":
    main()
