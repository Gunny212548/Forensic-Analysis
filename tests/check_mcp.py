"""End-to-end check of the read-only MCP server (app/mcp_server.py).

    python tests/check_mcp.py <scratch dir> [--repo DIR] [--usecase DIR]

Builds a throwaway store in <scratch dir> (gen_usecase's two files zipped
into one case, one account), then drives `python -m app.mcp_server` over its
real stdio transport and asserts what a client would rely on: the
handshake, every tool, every refusal, that stdout carries nothing but
JSON-RPC, and that each call landed in the hash-chained access log. Two
servers then write the log at once to check the cross-process lock - that
part needs Linux (fcntl), so it is skipped on a Windows host.

In the container (tests/ is not in the image):
    docker cp tests/. forensic-analyzer-forensic-analyzer-1:/tmp/fa-tests
    docker exec forensic-analyzer-forensic-analyzer-1 \
        python /tmp/fa-tests/check_mcp.py /tmp/mcp-check --repo /app --usecase /tmp/fa-tests
Nothing touches the real store.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
EMAIL, PASSWORD = "mcp-check@test.local", "mcp-check-throwaway-password"
failures: list[str] = []


def check(cond, what: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond:
        failures.append(what)


def setup(repo: Path, usecase_dir: Path, scratch: Path) -> tuple[dict, str, Path]:
    store, uc = scratch / "store", scratch / "usecase"
    store.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, str(usecase_dir / "gen_usecase.py"), str(uc)],
                   check=True, capture_output=True)
    zpath = uc / "nightfall.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("nightfall-auth.log", "nightfall-firewall.csv"):
            z.write(uc / name, name)
    env = {**os.environ, "DATA_DIR": str(store), "PYTHONPATH": str(repo)}
    subprocess.run([sys.executable, str(repo / "tools" / "create_user.py"), "add", EMAIL,
                    "--name", "MCP check", "--role", "analyst", "--password-stdin"],
                   input=PASSWORD + "\n", text=True, env=env, capture_output=True, check=True)
    code = (
        "import sys; sys.path.insert(0, sys.argv[1])\n"
        "from fastapi.testclient import TestClient\nfrom app.main import app\n"
        "c = TestClient(app)\n"
        f"c.post('/api/auth/login', json={{'email': '{EMAIL}', 'password': '{PASSWORD}'}})\n"
        "with open(sys.argv[2], 'rb') as fh:\n"
        "    m = c.post('/api/upload', files={'file': ('nightfall.zip', fh)}, data={'company_name': 'MCP check'}).json()\n"
        "import time\n"
        "for _ in range(1200):\n"
        "    if c.get('/api/cases/' + m['case_id']).json()['status'] in ('ready', 'failed'): break\n"
        "    time.sleep(0.25)\n"
        "print(m['case_id'])\n"
    )
    out = subprocess.run([sys.executable, "-c", code, str(repo), str(zpath)], env=env,
                         capture_output=True, text=True, check=True)
    return env, out.stdout.strip().splitlines()[-1], zpath


class Client:
    """A minimal MCP client: one request, one reply, in order."""

    def __init__(self, repo: Path, env: dict, actor: str = EMAIL):
        self.p = subprocess.Popen([sys.executable, "-m", "app.mcp_server", "--actor", actor],
                                  cwd=str(repo), env=env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  encoding="utf-8")
        self.n = 0
        self.raw_lines: list[str] = []

    def send(self, msg: dict | str) -> dict | None:
        text = msg if isinstance(msg, str) else json.dumps(msg)
        self.p.stdin.write(text + "\n")
        self.p.stdin.flush()
        if isinstance(msg, dict) and "id" not in msg:
            return None
        line = self.p.stdout.readline()
        self.raw_lines.append(line)
        return json.loads(line)

    def request(self, method: str, params: dict | None = None) -> dict:
        self.n += 1
        return self.send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}})

    def call(self, name: str, **arguments) -> tuple[bool, dict]:
        r = self.request("tools/call", {"name": name, "arguments": arguments})["result"]
        return r["isError"], json.loads(r["content"][0]["text"])

    def close(self) -> str:
        self.p.stdin.close()
        rest = self.p.stdout.read()
        self.p.wait(timeout=30)
        return rest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(HERE.parent))
    ap.add_argument("--usecase", default=str(HERE), help="directory holding gen_usecase.py")
    a = ap.parse_args()
    repo, scratch = Path(a.repo), Path(a.scratch)
    env, case_id, zpath = setup(repo, Path(a.usecase), scratch)
    store = Path(env["DATA_DIR"])
    print(f"case {case_id}")

    print("handshake")
    c = Client(repo, env)
    init = c.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                    "clientInfo": {"name": "check_mcp", "version": "1"}})["result"]
    check(init["protocolVersion"] == "2025-11-25", "negotiates the requested protocol version")
    check("tools" in init["capabilities"], "declares the tools capability")
    check("not the judge" in init["instructions"], "instructions state the assistant-not-judge rule")
    check(c.send({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None,
          "a notification gets no reply")
    tools = c.request("tools/list")["result"]["tools"]
    check(len(tools) == 12, f"12 tools listed (got {len(tools)})")
    check(all(t["annotations"]["readOnlyHint"] and not t["annotations"]["destructiveHint"]
              for t in tools), "every tool is annotated read-only")
    check(c.request("ping")["result"] == {}, "ping")

    print("tools")
    err, r = c.call("list_cases")
    check(not err and r["count"] == 1 and r["cases"][0]["case_id"] == case_id, "list_cases finds the case")
    err, r = c.call("get_case", case_id=case_id)
    digest = hashlib.sha256(zpath.read_bytes()).hexdigest()
    check(not err and r["custody"]["evidence_sha256"] == digest,
          "get_case: evidence digest equals SHA-256 of the uploaded bytes")
    check(r["custody"]["chain_intact"] is True, "get_case: custody chain intact")
    check(r["status"] == "ready" and r["members"] and len(r["members"]) == 2, "get_case: ready, 2 zip members")

    err, r = c.call("list_findings", case_id=case_id, limit=200)
    check(not err and r["total"] > 0, f"list_findings: {r.get('total')} findings")
    findings = r["findings"]
    lvls = [f["level"] for f in findings]
    check(lvls == sorted(lvls, key=lambda x: -["informational", "low", "medium", "high", "critical"].index(x)),
          "list_findings: most severe first")
    err, hi = c.call("list_findings", case_id=case_id, min_level="high")
    check(not err and hi["total"] > 0 and all(f["level"] in ("high", "critical") for f in hi["findings"]),
          "list_findings min_level=high returns only high/critical")
    check(all(f["admiralty"] for f in findings), "every finding carries an Admiralty grade")

    top = findings[0]
    err, ev = c.call("get_finding_events", case_id=case_id, finding_key=top["finding_key"], limit=200)
    check(not err and ev["total"] == top["rows"], f"get_finding_events: total {ev.get('total')} == finding rows {top['rows']}")
    check(all(row["rid"] == top["rule"] and row["raw"] and isinstance(row["row_id"], int) for row in ev["rows"]),
          "get_finding_events: every row is that rule's, with row_id and the original line")
    check(ev["evidence_sha256"] == digest, "get_finding_events carries the evidence digest")
    err, page = c.call("get_finding_events", case_id=case_id, finding_key=top["finding_key"], limit=1, offset=1)
    check(not err and len(page["rows"]) <= 1 and (not page["rows"] or page["rows"][0]["row_id"] == ev["rows"][1]["row_id"]),
          "get_finding_events pages by row order")

    err, r = c.call("get_source_profiles", case_id=case_id, ips=["10.20.30.40"])
    check(not err and r["profiles"] and r["profiles"][0]["srcip"] == "10.20.30.40", "get_source_profiles")
    err, r = c.call("get_risk_ranking", case_id=case_id)
    check(not err and any(r["ranking"].values()), "get_risk_ranking")
    err, r = c.call("get_attack_graph", case_id=case_id)
    check(not err and r["graph"]["edges"], "get_attack_graph has edges")
    err, r = c.call("get_escalations", case_id=case_id)
    check(not err and any(x["pattern"] == "credential-compromise" and x["srcip"] == "10.20.30.40"
                          and x["username"] == "root" for x in r["escalations"]),
          "get_escalations: the planted brute force -> root login")
    err, r = c.call("get_veris", case_id=case_id)
    check(not err and r["veris"] and "action" in r["veris"], "get_veris returns a record")
    err, r = c.call("get_rule", rule_id="R2000")
    check(not err and r.get("id") and r.get("ads"), "get_rule R2000 has Sigma id and ADS")
    err, r = c.call("get_custody", case_id=case_id)
    check(not err and r["status"]["chain_intact"] and len(r["entries"]) >= 2, "get_custody")
    err, r = c.call("get_analysis", case_id=case_id)
    check(not err and r["analysis"] is None, "get_analysis: none generated, said so")

    print("refusals")
    for label, args in [("path traversal", {"case_id": "../users"}),
                        ("unknown case", {"case_id": "case-20990101-000000-deadbeef"}),
                        ("unknown argument", {"case_id": case_id, "sql": "SELECT 1"})]:
        err, r = c.call("get_case", **args)
        check(err and r["error"], f"get_case refuses {label}: {r.get('error')}")
    err, r = c.call("get_finding_events", case_id=case_id, finding_key=top["finding_key"], limit=500)
    check(err, "limit above 200 refused")
    err, r = c.call("get_finding_events", case_id=case_id, finding_key="x|y|z")
    check(err, "malformed finding_key refused")
    err, r = c.call("get_rule", rule_id="R9999")
    check(err, "unknown rule refused")
    err, r = c.call("list_findings", case_id=case_id, min_level="severe")
    check(err, "bad enum refused")
    check(c.request("tools/call", {"name": "run_sql", "arguments": {}}).get("error", {}).get("code") == -32602,
          "unknown tool is a protocol error")
    check(c.request("resources/list").get("error", {}).get("code") == -32601, "unknown method -32601")
    check(c.send("{not json").get("error", {}).get("code") == -32700, "parse error -32700")
    calls = sum(1 for line in c.raw_lines if '"content"' in line)
    c.close()
    check(all(json.loads(line) for line in c.raw_lines if line.strip()), "stdout carried only JSON-RPC")

    print("access log")
    sys.path.insert(0, str(repo))
    os.environ["DATA_DIR"] = env["DATA_DIR"]
    from app.services import hashchain  # noqa: E402
    log = store / "mcp" / "access.jsonl"
    entries = hashchain.entries(log)
    check(len(entries) == calls, f"one access entry per tools/call ({len(entries)} vs {calls})")
    check(all(e["actor"] == EMAIL for e in entries), "actor recorded on every entry")
    check(sum(e["outcome"] == "refused" for e in entries) >= 7, "refusals are logged too")
    check(hashchain.verify(log)["intact"], "access log hash chain intact")

    bad = subprocess.run([sys.executable, "-m", "app.mcp_server", "--actor", "nobody@x"],
                         cwd=str(repo), env=env, capture_output=True, text=True, input="")
    check(bad.returncode == 2, "an actor that is not an account is refused at start")

    try:
        import fcntl  # noqa: F401
    except ImportError:
        print("  skip concurrent writers (no fcntl on this host)")
    else:
        print("concurrent writers")
        before = len(hashchain.entries(log))

        def burst():
            cl = Client(repo, env)
            cl.request("initialize", {"protocolVersion": "2025-11-25"})
            for _ in range(25):
                cl.call("get_rule", rule_id="R1000")
            cl.close()

        threads = [threading.Thread(target=burst) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        v = hashchain.verify(log)
        check(len(hashchain.entries(log)) == before + 75 and v["intact"],
              f"3 servers x 25 calls: chain intact, {len(hashchain.entries(log)) - before} entries ({v['problem']})")

    print(f"\n{'MCP CHECK OK' if not failures else f'{len(failures)} FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
