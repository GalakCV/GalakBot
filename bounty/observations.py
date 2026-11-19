"""Output adapters identify candidates; independent triage never assumes impact."""
import re


def candidates(skill, phase, text, host):
    for line in text.splitlines():
        if skill == "infra" and phase == "takeover" and "\tservice=" in line:
            yield {"host": line.split("\t")[0], "title": "Takeover candidate", "observation": line}
        elif skill == "infra" and phase == "tls" and line.startswith("WEAK:"):
            yield {"host": host, "title": "Legacy TLS protocol accepted", "observation": line}
        elif skill == "cloud" and phase == "bucket-exposure" and line.startswith("PUBLIC  "):
            yield {"host": host, "title": "Possible public bucket listing", "observation": line}
        elif skill == "api-testing" and phase == "auth-enforcement":
            match = re.fullmatch(r"\s*(\d{3})\s+(\d+)\s+(/\S*)\s*", line)
            if match and match[1] == "200" and int(match[2]) > 0:
                yield {"host": host, "title": "Review unauthenticated GET " + match[3], "observation": line}
