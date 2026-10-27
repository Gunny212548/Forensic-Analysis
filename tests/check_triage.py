"""The AI's review of each suggestion (app/services/triage.py, specs/ai_triage.md).

    python tests/check_triage.py <scratch> [--repo DIR]

No model: llm._chat is replaced by a fake that answers inside the schema it is
given, so what is checked is the machinery - the facts handed over (a
destination's popularity among internal hosts tells a staff cloud service from
a one-host upload), the schema's enums (only this batch's suggestion and fact
ids), the grounding check, the file kept with the case and deleted with it, a
model that cannot be reached leaving the case ready, and the AI's advice kept
on the analyst's review line (Q80). The model's own accuracy is measured on the
synthetic Check Point quarter, not here. Since specs/ai_review_coverage.md: no cap, every rule
first, retries then one by one, Review again, the review queued after the case is ready.
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

    print("a model that cannot be reached: retried, then one by one, every failure listed")

    async def down(*a, **k):
        raise llm.AnalysisError("connection refused")

    llm._chat = down
    counts = []
    res = triage.review_case(cid, findings, on_progress=lambda *c: counts.append(c))
    check(res.get("reviewed") == 0 and len(res.get("failed") or {}) == 13 and res.get("status") == "done",
          f"each of the 13 suggestions listed with its error; review_case does not raise ({len(res.get('failed') or {})})")
    check(counts[-1] == (0, 13, 13), f"failed suggestions counted in the progress ({counts[-1:]})")

    print("specs/ai_review_coverage.md: every suggestion, every rule first, retries, Review again")
    cid2 = storage.create_case("many.csv", "csv", 1, company_id=co)["case_id"]
    con = db.init(cid2)
    n = 0
    for rid_, k in (("R3001", 85), ("R2002", 3), ("R2003", 2)):   # 90 suggestions over three rules
        for i in range(k):
            con.execute("INSERT INTO raw_events (row_id, ts, srcip, dstip, verdict, bytes_sent) "
                        "VALUES (?, TIMESTAMP '2026-09-26 02:00:00', ?, '198.51.100.9', 'allow', 1)",
                        [n, f"10.9.{rid_[-1]}.{i}"])
            con.execute("INSERT INTO findings (row_id, rid, lvl, descr, mitre) VALUES (?, ?, 2, 'x', ['T1041'])",
                        [n, rid_])
            n += 1
    con.close()
    storage.update_case(cid2, status="ready")
    many = case_views.findings_view(cid2, storage.load_manifest(cid2), assign_ids=False)
    order = [f["rid"] for f in triage._order(many)]
    check(len(many) == 90 and set(order[:3]) == {"R3001", "R2002", "R2003"},
          f"every rule's first suggestion comes first ({order[:4]})")
    calls, drop = [], {"S7"}

    async def flaky(client, payload, *a, **k):
        ids = payload["_schema"]["properties"]["reviews"]["items"]["properties"]["suggestion"]["enum"]
        calls.append(list(ids))
        keep = [x for x in ids if not (x in drop and len(ids) > 1)]   # S7 only answered on its own
        return {"choices": [{"message": {"content": json.dumps({"reviews": [
            {"suggestion": x, "why_it_fired": "w", "cause": "c", "assessment": "uncertain", "reasons": [],
             "matches_false_positive": "none", "suggested_decision": "undecided", "reject_reason": "none",
             "check_next": "n"} for x in keep]})}, "finish_reason": "stop"}]}

    llm._chat = flaky
    res = triage.review_case(cid2, many)
    check(res["reviewed"] == 90 and not res["failed"], f"all 90 reviewed - no cap ({res['reviewed']})")
    check(["S7"] in calls, "a suggestion the answer left out is retried, then sent on its own")
    saved = triage.load(cid2)
    check(saved.get("status") == "done" and saved.get("reviewed") == 90, "the file says done, with every one")

    # A failure outside a batch, after two batches, keeps the advice those batches wrote.
    def stop_after_two(done, total, failed):
        if done >= 10:
            raise OSError("disk full")

    res = triage.review_case(cid2, many, on_progress=stop_after_two)
    saved = triage.load(cid2)
    check(res.get("status") == "failed" and res["reviewed"] == 10 and saved.get("reviewed") == 10
          and "disk full" in (res.get("error") or ""),
          f"a failure after two batches keeps their advice ({res.get('reviewed')}, {saved.get('reviewed')})")

    # One suggestion that always fails, then Review again sends only it.
    bad = triage._order(many)[11]
    bad_key = bad["key"]

    async def one_bad(client, payload, *a, **k):
        if any(f"Source {bad['srcip']} is" in m["content"] for m in payload["messages"]):
            raise llm.AnalysisError("the model timed out")
        return await flaky(client, payload)

    drop.clear()
    llm._chat = one_bad
    res = triage.review_case(cid2, many)
    check(res["reviewed"] == 89 and list(res["failed"]) == [bad_key],
          f"the one that keeps failing is listed, the rest reviewed ({res['reviewed']}, {list(res['failed'])})")
    v = {f["key"]: f for f in case_views.findings_view(cid2, storage.load_manifest(cid2), assign_ids=False)}
    check(v[bad_key]["ai_state"] == "failed" and "timed out" in (v[bad_key]["ai_error"] or ""),
          "the finding says it was not reviewed, and why")
    calls.clear()
    llm._chat = flaky
    res = triage.review_case(cid2, many, again=True)
    check(res["reviewed"] == 90 and len(calls) == 1 and len(calls[0]) == 1,
          f"Review again sends only the one without advice ({[len(c) for c in calls]})")

    print("in the background, after the case is ready (C-D2)")
    calls.clear()
    triage.enqueue(cid2)
    check(storage.load_manifest(cid2)["ai_review"]["status"] in ("queued", "running", "done"), "queued on the manifest")
    triage.wait_idle(60)
    a = storage.load_manifest(cid2)["ai_review"]
    check(a["status"] == "done" and a["done"] == 90 and a["total"] == 90 and a["failed"] == 0,
          f"the manifest counts it to the end ({a})")
    check(sum(len(c) for c in calls) == 90, "a fresh review sends every suggestion again (new findings, new advice)")
    storage.update_case(cid2, ai_review={**a, "status": "running"})
    check(triage.state_of(cid2, storage.load_manifest(cid2), "R9|x|y", {}, {}) == "pending",
          "a suggestion still to come is pending while the review runs")
    storage.update_case(cid2, ai_review={**a, "status": "done"})
    check(storage.case_files(storage.customer_dir(co), cid)
          and any(p.name.endswith(".triage.json") for p in storage.case_files(storage.customer_dir(co), cid)),
          "the review file is one of the case's files - deleted with it")

    print("\nTRIAGE OK" if not FAILED else f"\n{len(FAILED)} FAILED")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
