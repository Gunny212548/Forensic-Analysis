"""Behaviour profiles (app/services/profiles.py, specs/behaviour_profiles.md).

    python tests/check_profiles.py [--repo DIR]

In-memory DuckDB with the app's own schema and hand-built rows, so every
expected number is known: the sliding 1 / 10 / 60-minute windows and their
edges, ranks against a crowd and none below MIN_CROWD, "n/a" where an address
has no events of that kind, bytes to public addresses over R2007's ranges, and
the one-line context. Needs duckdb only. The end-to-end figures on the planted
gen_usecase attack are asserted by tests/check_mcp.py (get_profile).
"""

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    sys.path.insert(0, ap.parse_args().repo)
    import duckdb

    from app.services import db, profiles, rules

    print("public-address ranges are R2007's")
    r2007 = dict(rules.RULES)["R2007"]
    check(rules.IPV4_RE in r2007 and rules.NON_PUBLIC_IPV4_RE in r2007,
          "IPV4_RE and NON_PUBLIC_IPV4_RE appear verbatim in R2007's SQL")

    t0 = datetime(2026, 2, 15, 5, 0, 0)
    rows: list[tuple] = []

    def ev(src, offset_s, action=None, user=None, verdict=None, dst=None, port=None, sent=None):
        rows.append((len(rows), t0 + timedelta(seconds=offset_s), src, dst, port, user, action, verdict, sent))

    # 24 ordinary sources: one mistyped password each, an hour apart.
    for i in range(24):
        ev(f"10.0.0.{i + 1}", i * 3600, "auth_failed", f"user{i}")
        ev(f"10.0.0.{i + 1}", i * 3600 + 30, "auth_success", f"user{i}")
    # The attacker: 30 failures 4 s apart on 3 accounts, then a success.
    for i in range(30):
        ev("203.0.113.9", 10 + i * 4, "auth_failed" if i % 3 else "invalid_user", f"acct{i % 3}")
    ev("203.0.113.9", 200, "auth_success", "acct1")
    # Window edges: failures exactly 60 s apart share a 1-minute window,
    # 61 s apart do not.
    ev("10.9.9.1", 0, "auth_failed", "a")
    ev("10.9.9.1", 60, "auth_failed", "a")
    ev("10.9.9.2", 0, "auth_failed", "b")
    ev("10.9.9.2", 61, "auth_failed", "b")
    # A firewall-only source: refused on 3 ports, then sends to a public and
    # a private address.
    for i, port in enumerate((22, 23, 445)):
        ev("10.5.5.5", i, verdict="deny", dst="10.1.1.1", port=str(port))
    ev("10.5.5.5", 100, verdict="allow", dst="8.8.8.8", port="443", sent=5000)
    ev("10.5.5.5", 110, verdict="allow", dst="192.168.1.10", port="445", sent=7000)
    # An account signing in from 5 addresses inside an hour, then once more
    # from a sixth two hours later; the name in two spellings.
    for i in range(5):
        ev(f"198.51.100.{i + 1}", 3600 + i * 600, "auth_success", "Roamer" if i % 2 else "roamer")
    ev("198.51.100.99", 3600 + 3 * 3600, "auth_success", "roamer")

    con = duckdb.connect()
    con.execute(db.SCHEMA)
    con.executemany("INSERT INTO raw_events (row_id, ts, srcip, dstip, dstport, username, action, verdict, "
                    "bytes_sent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    n = profiles.build(con)
    check(n == 24 + 1 + 2 + 1 + 6, f"one profile per source address ({n})")

    def get(ip):
        return profiles.get(con, ip, db._fmt_ts)

    print("the attacker against the crowd")
    a = get("203.0.113.9")["sign_ins"]
    # The window is [t, t + 1 min], ends included: 10 s, 14 s ... 70 s is 16.
    check((a["fail_max_1m"], a["fail_max_10m"], a["fail_max_60m"]) == (16, 30, 30),
          f"30 failures 4 s apart: 16 in any minute, 30 in 10 and 60 ({a['fail_max_1m']}/"
          f"{a['fail_max_10m']}/{a['fail_max_60m']})")
    check(a["auth_failed"] + a["invalid_user"] == 30 and a["accounts_failed"] == 3,
          "failures and unknown accounts counted together, on 3 accounts")
    check(a["success_after_fail_gap_s"] == 190, f"success 190 s after the first failure ({a.get('success_after_fail_gap_s')})")
    rank = a["rank"]
    check(isinstance(rank, dict) and rank["among"] == 33
          and rank["percent_of_addresses_below"]["fail_max_10m"] >= 96,
          f"ranked among the 33 sources with sign-ins, above at least 96% ({rank})")
    # Ties share a rank: below an address with 1 failure are only the 6
    # roaming-account addresses, which signed in but never failed.
    o = get("10.0.0.3")["sign_ins"]
    check(o["fail_max_1m"] == 1 and o["rank"]["percent_of_addresses_below"]["fail_max_1m"] == 18.2,
          f"an ordinary source: 1 failure, above only the 6 of 33 with none "
          f"({o['rank']['percent_of_addresses_below']['fail_max_1m']})")

    print("window edges")
    check(get("10.9.9.1")["sign_ins"]["fail_max_1m"] == 2, "60 s apart: one 1-minute window")
    check(get("10.9.9.2")["sign_ins"]["fail_max_1m"] == 1, "61 s apart: two windows")

    print("n/a, bytes")
    fw = get("10.5.5.5")
    check(fw["sign_ins"].startswith("n/a"), "no sign-in events -> sign-ins n/a, not zeros")
    t = fw["traffic"]
    check(t["refused"] == 3 and t["refused_ports"] == 3 and t["refused_max_1m"] == 3, "3 refusals on 3 ports in a minute")
    check(t["bytes_total"] == 12000 and t["bytes_public"] == 5000,
          f"bytes: 12000 sent, 5000 of them to a public address ({t['bytes_public']})")
    check(isinstance(t["rank"], str) and "fewer than 20" in t["rank"],
          f"one firewall source is no crowd: not ranked ({t['rank']})")
    check(get("10.0.0.1")["traffic"].startswith("n/a"), "no firewall events -> traffic n/a")
    check(get("192.0.2.250") is None, "an address with no events has no profile")

    print("context line")
    lines = profiles.context_lines(con, {"203.0.113.9", "10.5.5.5", "10.0.0.1"})
    check("most 16 in 1 min / 30 in 10 min" in lines.get("203.0.113.9", "")
          and "more than" in lines["203.0.113.9"], f"attacker line: {lines.get('203.0.113.9')}")
    check("refused 3 times" in lines.get("10.5.5.5", ""), f"firewall line: {lines.get('10.5.5.5')}")

    print("top")
    top = profiles.top(con, "fail_max_10m", 3, db._fmt_ts)
    check([p["srcip"] for p in top][:1] == ["203.0.113.9"], "top by failures in 10 min: the attacker first")
    try:
        profiles.top(con, "severity", 3, db._fmt_ts)
        check(False, "an unranked fact is refused")
    except ValueError:
        check(True, "an unranked fact is refused")

    print("accounts")
    r = profiles.get_account(con, "ROAMER", db._fmt_ts)
    s = r["sign_ins"] if r else {}
    check(r is not None and r["account"] == "roamer" and s.get("auth_success") == 6,
          "an account is matched case-insensitively and its two spellings are one account")
    check(s.get("sources_succeeded") == 6 and s.get("success_sources_max_60m") == 5,
          f"6 sources in all, 5 of them inside one hour ({s.get('sources_succeeded')}, "
          f"{s.get('success_sources_max_60m')})")
    check(r["hosts"].startswith("n/a"), "no host in the events -> hosts n/a")
    acc = profiles.get_account(con, "acct1", db._fmt_ts)["sign_ins"]
    check(acc["sources_failed"] == 1 and acc["fail_max_1m"] == 6,
          f"acct1: failures from one source, 6 in a minute ({acc['fail_max_1m']})")
    rank = r["sign_ins"]["rank"]
    check(isinstance(rank, dict) and rank["among"] >= 20
          and rank["percent_of_accounts_below"]["success_sources_max_60m"] > 90,
          f"roamer ranked among {rank['among'] if isinstance(rank, dict) else rank} accounts, "
          "above 90% on sources within an hour")
    top = profiles.top_accounts(con, "success_sources_max_60m", 1, db._fmt_ts)
    check(top and top[0]["account"] == "roamer", "top accounts by sources within an hour: roamer")
    lines = profiles.account_lines(con, {"Roamer", "user3"})
    check("signed in from 6 sources, most 5 within an hour" in lines.get("roamer", "")
          and "user3" in lines, f"account lines: {lines}")
    check(profiles.get_account(con, "nobody", db._fmt_ts) is None, "an unknown account has no profile")

    print("a case processed before profiles existed")
    old = duckdb.connect()
    old.execute(db.SCHEMA)
    try:
        profiles.get(old, "1.2.3.4", db._fmt_ts)
        check(False, "says it needs a re-process")
    except LookupError as exc:
        check("re-process" in str(exc), f"says it needs a re-process ({exc})")
    check(profiles.context_lines(old, {"1.2.3.4"}) == {}, "...and the events table simply shows no line")

    print()
    print(f"{len(FAILED)} FAILED" if FAILED else "PROFILES OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
