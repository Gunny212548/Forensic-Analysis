"""Spike (a): the 19 SigmaHQ signinlogs rules on our real Entra files, per rule:
applicable (every field the rule reads exists in the file) and matches.

The field mapping here is a PROTOTYPE written from the files' own keys and the
Log Analytics column names the rules use; it is not yet checked against
Microsoft's SigninLogs table reference.
"""
import json
import re
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import duckdb
from duck_dialect import DuckDialect
from sigma.collection import SigmaCollection

# Sigma field -> Azure Monitor JSON key (flattened)
JSON_MAP = {
    "ResultType": "resultType", "ResultDescription": "resultDescription",
    "userAgent": "properties.userAgent", "Username": "properties.userPrincipalName",
    "AuthenticationRequirement": "properties.authenticationRequirement",
    "conditionalAccessStatus": "properties.conditionalAccessStatus",
    "ResourceDisplayName": "properties.resourceDisplayName", "RiskState": "properties.riskState",
    "DeviceDetail.trusttype": "properties.deviceDetail.trustType",
    "DeviceDetail.isCompliant": "properties.deviceDetail.isCompliant",
    "DeviceDetail.deviceId": "properties.deviceDetail.deviceId",
    "NetworkLocationDetails": "properties.networkLocationDetails",
    "ClientApp": "properties.clientAppUsed",
}
# Sigma field -> Entra portal CSV header
CSV_MAP = {
    "ResultType": "Sign-in error code", "ResultDescription": "Failure reason",
    "Status": "Status", "userAgent": "User agent", "Username": "Username",
    "AuthenticationRequirement": "Authentication requirement",
    "conditionalAccessStatus": "Conditional Access", "ResourceDisplayName": "Resource",
    "DeviceDetail.trusttype": "Join Type", "DeviceDetail.isCompliant": "Compliant",
    "DeviceDetail.deviceId": "Device ID", "ClientApp": "Client app",
}


def flatten(d, pre=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict) and v:
            out.update(flatten(v, f"{pre}{k}."))
        else:
            out[f"{pre}{k}"] = None if v is None else (json.dumps(v) if isinstance(v, (list, dict)) else str(v))
    return out


def load_json(con, files):
    rows = [flatten(json.loads(l)) for f in files for l in open(f, encoding="utf-8") if l.strip()]
    cols = sorted({k for r in rows for k in r})
    con.execute("CREATE TABLE src (" + ", ".join(f'"{c}" VARCHAR' for c in cols) + ")")
    con.executemany(f"INSERT INTO src VALUES ({','.join('?' * len(cols))})", [[r.get(c) for c in cols] for r in rows])
    return set(cols)


def load_csv(con, f):
    con.execute(f"CREATE TABLE src AS SELECT * FROM read_csv('{f}', all_varchar=true, header=true)")
    return {r[0] for r in con.execute("SELECT column_name FROM (DESCRIBE src)").fetchall()}


def run(label, con, cols, mapping, rules):
    present = {s: t for s, t in mapping.items() if t in cols}
    sel = ", ".join(f'"{t}" AS "{s}"' for s, t in present.items())
    con.execute(f"CREATE VIEW logs AS SELECT {sel} FROM src")
    n = con.execute("SELECT count(*) FROM src").fetchone()[0]
    print(f"\n== {label}: {n} rows; Sigma fields available {sorted(present)}")
    for title, q, fields in rules:
        missing = [f for f in fields if f not in present]
        if missing:
            print(f"  n/a  {title}  (no {', '.join(missing)})")
            continue
        hits = con.execute(q.replace("SELECT *", "SELECT count(*)")).fetchone()[0]
        print(f"  {hits:4} {title}")


def main():
    b = DuckDialect()
    rules = []
    for p in sorted(pathlib.Path(sys.argv[1]).rglob("*.yml")):
        text = p.read_text(encoding="utf-8")
        if "service: signinlogs" not in text:
            continue
        q = b.convert(SigmaCollection.from_yaml(text))[0]
        fields = sorted(set(re.findall(r'"([^"]+)"', re.sub(r"'(?:[^']|'')*'", "''", q))) - {"logs"})
        rules.append((re.search(r"^title: (.*)$", text, re.M).group(1), q, fields))

    samples = pathlib.Path("D:/forensic-analyzer-s4/tests/samples/entra-azure-monitor")
    con = duckdb.connect()
    run("Azure Monitor JSON (Splunk attack_data, 2 files)", con,
        load_json(con, sorted(samples.glob("*.jsonl"))), JSON_MAP, rules)
    con = duckdb.connect()
    run("Entra portal CSV (KM23 InteractiveSignIns)", con,
        load_csv(con, "D:/forensic system/Logtest/2026-02/KM23 ITSupport_InteractiveSignIns_2026-06-04_2026-06-11.csv"),
        CSV_MAP, rules)


if __name__ == "__main__":
    main()
