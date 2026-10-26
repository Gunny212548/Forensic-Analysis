"""The AI's review of each suggestion (app/services/triage.py, specs/ai_triage.md).

    python tests/check_triage.py <scratch> [--repo DIR]

No model: llm._chat is replaced by a fake that answers inside the schema it is
given, so what is checked is the machinery - the facts handed over (a
destination's popularity among internal hosts tells a staff cloud service from
a one-host upload), the schema's enums (only this batch's suggestion and fact
ids), the grounding check, the file kept with the case and deleted with it, a
model that cannot be reached leaving the case ready, and the AI's advice kept
on the analyst's review line (Q80). The model's own accuracy is measured on the
synthetic Check Point quarter, not here.
"""

import argparse
import json
import os
import sys
from pathlib import Path

FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    args = ap.parse_args()
    scratch = Path(args.scratch)
    os.environ["DATA_DIR"] = str(scratch / "data")
    os.environ["AUTH_DIR"] = str(scratch / "auth")
    os.environ["LLM_PROVIDER"] = "ollama"
    sys.path.insert(0, args.repo)
    from app.services import case_views, db, llm, review, storage, triage

    co = storage.create_company("Triage Co")["company_id"]
    cid = storage.create_case("t.csv", "csv", 1, company_id=co)["case_id"]
    con = db.init(cid)
    rows = [  # one host uploads to an address nobody else uses; 12 staff sync to a shared one
        (0, "192.168.1.5", "198.51.100.88", 400_000_000),
    ] + [(i, f"192.168.1.{100 + i}", "13.107.42.35", 80_000_000) for i in range(1, 13)]
    for rid_, src, dst, sent in rows:
        con.execute("INSERT INTO raw_events (row_id, ts, srcip, dstip, verdict, bytes_sent) "
                    "VALUES (?, TIMESTAMP '2026-09-26 02:00:00', ?, ?, 'allow', ?)", [rid_, src, dst, sent])
        con.execute("INSERT INTO findings (row_id, rid, lvl, descr, mitre) VALUES (?, 'R3001', 2, ?, ['T1041'])",
                    [rid_, f"Large outbound transfer ({sent} bytes) {src} -> {dst}"])
    con.close()
    storage.update_case(cid, status="ready")
    m = storage.load_manifest(cid)
    findings = case_views.findings_view(cid, m, assign_ids=False)

    print("the facts handed over")
    exfil = next(f for f in findings if f["srcip"] == "192.168.1.5")
    sync = next(f for f in findings if f["srcip"] == "192.168.1.101")
    con = db.connect(cid, read_only=True)
    fx, fs = triage.facts(con, exfil), triage.facts(con, sync)
    con.close()
    check(any("reached by 1 internal host" in x for x in fx), "the upload's destination: one internal host")
    check(any("reached by 12 internal host" in x for x in fs), "the sync's destination: twelve internal hosts")
    check(any("false positives" in x and "cloud" in x.lower() for x in fx),
          "the rule's documented false positives are among the facts")

    print("the schema only allows this batch's ids")
    sch = triage._schema([("S1", ["a", "b"], ["fp one"]), ("S2", ["c"], [])])
    item = sch["properties"]["reviews"]["items"]["properties"]
    check(item["suggestion"]["enum"] == ["S1", "S2"]
          and item["reasons"]["items"]["properties"]["facts"]["items"]["enum"] == ["S1.f1", "S1.f2", "S2.f1"]
          and set(item["matches_false_positive"]["enum"]) == {"fp one", "none"},
          "suggestion ids, fact ids and false positives are enums")

    print("a review end to end, with a fake model")
    seen_payloads = []

    async def fake_chat(client, payload, *a, **k):
        seen_payloads.append(payload)
        ids = payload["_schema"]["properties"]["reviews"]["items"]["properties"]["suggestion"]["enum"]
        blocks = {b.split(":", 1)[0].strip(): b for b in payload["messages"][1]["content"].split("Suggestion ")[1:]}

        def one(s):  # decides from the facts, as the model is asked to
            attack = "reached by 1 internal host" in blocks[s]
            return {"suggestion": s, "why_it_fired": "over 50 MB to one address",
                    "cause": "a one-host upload" if attack else "203.0.113.250 is a staff cloud service",
                    "assessment": "likely attack" if attack else "likely benign",
                    "reasons": [{"text": "how many hosts use it", "facts": [f"{s}.f5"] + (["S2.f1"] if s == "S1" else [])}],
                    "matches_false_positive": "none", "suggested_decision": "accept" if attack else "reject",
                    "reject_reason": "none" if attack else "misinterpretation", "check_next": "the destination"}
        reviews = [one(s) for s in ids]
        return {"choices": [{"message": {"content": json.dumps({"reviews": reviews})},
                             "finish_reason": "stop"}]}

    llm._chat = fake_chat
    counts = []
    res = triage.review_case(cid, findings, on_progress=lambda *c: counts.append(c))
    check(res.get("reviewed") == 13 and not res.get("errors"), f"13 suggestions reviewed ({res.get('reviewed')})")
    check(len(seen_payloads) == 3 and all(p["_schema"] for p in seen_payloads), "in batches of 5, each with its schema")
    check(counts == [(0, 13, 0), (5, 13, 0), (10, 13, 0), (13, 13, 0)],
          f"progress counted before the first batch and after each ({counts})")
    check(triage.path(cid).exists(), "kept with the case")
    benign = [r for r in res["items"].values() if r["assessment"] == "likely benign"]
    check(len(benign) == 12 and all(r["ungrounded"] == ["203.0.113.250"] for r in benign),
          "an address none of the facts holds is flagged")
    s1 = [r for r in res["items"].values() if r["suggestion"] == "S1"]
    check(len(s1) == 1 and s1[0]["cited_elsewhere"] == ["S2.f1"],
          "a fact of another suggestion in the batch is listed as cited elsewhere")
    view = {f["key"]: f for f in case_views.findings_view(cid, m, assign_ids=False)}
    check(view[exfil["key"]]["ai_review"]["assessment"] == "likely attack", "the advice is on the suggestion")

    print("the advice is kept on the analyst's review line (Q80)")
    entry = review.record_review(cid, exfil["key"], "accept", "a@x", ai=triage.assessment_of(cid, exfil["key"]))
    check(entry["ai"]["assessment"] == "likely attack" and entry["ai"]["suggested_decision"] == "accept",
          "assessment and suggestion recorded with the decision")

    print("a model that cannot be reached")

    async def down(*a, **k):
        raise llm.AnalysisError("connection refused")

    llm._chat = down
    counts = []
    res = triage.review_case(cid, findings, on_progress=lambda *c: counts.append(c))
    check(res.get("reviewed") == 0 and len(res.get("errors") or []) == 3,
          "every batch's failure recorded; review_case does not raise")
    check(counts[-1] == (13, 13, 3), f"failed batches counted in the progress ({counts[-1:]})")

    print("the count reaches the case's progress (pipeline.Progress.ai)")
    from app.services import pipeline
    pg = pipeline.Progress(cid)
    pg.set("ai", 99, force=True)
    pg.ai(5, 13, 1)
    p = storage.load_manifest(cid)["progress"]
    check(p["stage"] == "ai" and p["pct"] == 99 and p["ai"]["done"] == 5 and p["ai"]["total"] == 13
          and p["ai"]["failed"] == 1 and p["ai"]["model"], f"stage, 99% and the count on the manifest ({p})")
    pg.ai(10, 13, 1)
    check(storage.load_manifest(cid)["progress"]["ai"]["done"] == 10, "the next batch is written at once, not throttled")
    check(storage.case_files(storage.customer_dir(co), cid)
          and any(p.name.endswith(".triage.json") for p in storage.case_files(storage.customer_dir(co), cid)),
          "the review file is one of the case's files - deleted with it")

    print("\nTRIAGE OK" if not FAILED else f"\n{len(FAILED)} FAILED")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
