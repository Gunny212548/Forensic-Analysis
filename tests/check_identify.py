"""What each log file is identified as (IAI-92, app/services/identify.py).

    python tests/check_identify.py [--corpus]

Every file must be identified as its own log source - in Sigma logsource
terms, with a custom product where the taxonomy has none - and as no other;
files that are not a known log must come back unrecognised. No network, no
store: identification reads only the head of each file.

- tests/samples (committed): Splunk attack_data captures of formats with no
  reader yet (Cisco ASA, Cisco FTD eStreamer, Windows Security, Sysmon,
  CrowdStrike), the Entra ID Azure Monitor captures, and gen_usecase's
  ground truth (generated into a temp dir);
- negatives: gen_usecase's nested JSON (no documented profile), a README, a
  JSON object that is not log records, ESXi-style lines no format documents;
- --corpus: the real customer files the documented profiles were built on,
  at the paths CLAUDE.md names (never committed - skipped when absent).
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from app.services import identify  # noqa: E402

FAILED: list[str] = []
S = REPO / "tests" / "samples"

FIREWALL = {"category": "firewall"}
# (name, path, kind as upload decides it, expected status, expected sigma, expected custom)
CASES = [
    ("Cisco ASA syslog", S / "attack-data/cisco_asa_generic_logs.log", "log", "no_reader", FIREWALL, "cisco_asa"),
    ("Cisco FTD eStreamer JSON", S / "attack-data/ftd_connection_events.log", "log", "no_reader", FIREWALL, "cisco_ftd"),
    ("Windows Security (Splunk text)", S / "attack-data/windows-security.log", "log", "no_reader",
     {"product": "windows", "service": "security"}, None),
    ("Windows Sysmon event XML", S / "attack-data/windows-sysmon.log", "log", "no_reader",
     {"product": "windows", "service": "sysmon"}, None),
    ("CrowdStrike Falcon FDR", S / "attack-data/crowdstrike_falcon.log", "log", "no_reader", {}, "crowdstrike_falcon"),
    ("Entra ID Azure Monitor JSON", S / "entra-azure-monitor/azure_ad_distributed_spray.jsonl", "json", "supported",
     {"product": "azure", "service": "signinlogs"}, None),
    ("Entra ID Azure Monitor JSON (2)", S / "entra-azure-monitor/azuread_signin.jsonl", "json", "supported",
     {"product": "azure", "service": "signinlogs"}, None),
]

LOGTEST = Path("D:/forensic system/Logtest")
CORPUS = [
    ("PAN-OS traffic CSV", LOGTEST / "2026-01/2026 SUMMITGROUP info Virus/Data log Firewall paloalto/log(13).csv",
     "csv", "supported", FIREWALL, "paloalto_panos"),
    ("Check Point SmartConsole CSV", Path("D:/logtest/Logs_Jun_24__2026_11_09_44_102_AM_Logs_Table.csv"),
     "csv", "supported", FIREWALL, "checkpoint_smartconsole"),
    ("FortiGate traffic", Path("D:/Trafficlog/fortigate log-20260917T104408Z-1-001/fortigate log/Trafficlogs/"
                               "FG200FT923907508(root)_tlog_20260301-2219-20260302-0106.log"),
     "log", "supported", FIREWALL, "fortinet_fortigate"),
    ("Entra ID sign-in CSV", LOGTEST / "2026-02/KM23 ITSupport_InteractiveSignIns_2026-06-04_2026-06-11.csv",
     "csv", "supported", {"product": "azure", "service": "signinlogs"}, None),
    ("Exchange message trace CSV", LOGTEST / "2026-02/Doc/KM23_MessageTraceResult-Rev01.csv",
     "csv", "supported", {"product": "m365", "service": "exchange"}, None),
    ("VMware ESXi auth.log", LOGTEST / "2026-01/2026 SUMMITGROUP info Virus/log esxi 131/log/auth.log",
     "log", "supported", {}, "vmware_esxi"),
    ("PAN-OS saved as UTF-16 .txt", LOGTEST, "log", "supported", FIREWALL, "paloalto_panos"),
]


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def run(name, path, kind, status, sigma, custom) -> None:
    r = identify.identify(path, kind)
    got = (r["status"], r["sigma"], r["custom"])
    check(got == (status, sigma, custom),
          f"{name}: {r['status']} {r['sigma']} {r['custom'] or ''} - {r['evidence'][:90]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", action="store_true", help="also the real customer files, where present")
    args = ap.parse_args()

    print("committed samples")
    for c in CASES:
        run(*c)

    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        subprocess.run([sys.executable, str(REPO / "tests" / "gen_usecase.py"), str(t / "uc")],
                       check=True, capture_output=True)
        print("gen_usecase ground truth")
        run("nightfall-auth.log", t / "uc/nightfall-auth.log", "log", "supported",
            {"product": "linux", "service": "sshd"}, None)
        run("nightfall-firewall.csv", t / "uc/nightfall-firewall.csv", "csv", "supported", FIREWALL, "paloalto_panos")
        run("nightfall-firewall.json", t / "uc/nightfall-firewall.json", "json", "supported", FIREWALL, "paloalto_panos")

        print("not a known log: unrecognised, never guessed")
        run("nested JSON, no documented profile", t / "uc/nightfall-firewall-nested.jsonl.gz", "json",
            "unrecognised", {}, None)
        (t / "readme.txt").write_text("This is a note about the case.\nNothing here is a log.\n", encoding="utf-8")
        run("a text note", t / "readme.txt", "log", "unrecognised", {}, None)
        (t / "config.json").write_text('{"settings": {"theme": "dark", "retention_days": 30}}', encoding="utf-8")
        run("a JSON object that is not log records", t / "config.json", "json", "unrecognised", {}, None)
        (t / "hostd.log").write_text(
            "2026-01-10T13:13:32.123Z info hostd[2099100] [Originator@6876 sub=Vimsvc.TaskManager] Task Created\n"
            "2026-01-10T13:13:33.456Z verbose hostd[2099100] [Originator@6876 sub=PropertyProvider] RecordOp\n",
            encoding="utf-8")
        run("ESXi hostd lines (no documented format)", t / "hostd.log", "log", "unrecognised", {}, None)
        (t / "header.csv").write_text("Name,Value,Comment\nalpha,1,first\n", encoding="utf-8")
        run("a CSV with an unknown header", t / "header.csv", "csv", "unrecognised", {}, None)

    if args.corpus:
        print("real customer files (not committed)")
        for c in CORPUS:
            if c[0].startswith("PAN-OS saved as UTF-16"):
                hits = list(LOGTEST.rglob("log(8)-01.txt"))
                if not hits:
                    print(f"  skip {c[0]}: not found")
                    continue
                c = (c[0], hits[0], *c[2:])
            if not c[1].exists():
                print(f"  skip {c[0]}: {c[1]} not found")
                continue
            run(*c)

    print()
    if FAILED:
        print(f"{len(FAILED)} FAILED")
        return 1
    print("IDENTIFY OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
