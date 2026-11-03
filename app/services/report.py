"""The forensic report draft of a project (specs/forensic_report.md, IAI-72 / IAI-73).

The system writes a **draft** - an editable Word file the analyst finishes in Word (R-D0,
R-D3). One per project (R-D1), made only when every suggestion of every case is decided and
the question is written (R-D2), from the skeleton the administrator uploaded (R-D11). Every
section is filled from records the system already keeps, from the confirmed groups only
(gotcha #10); the Executive Summary is the local model's draft (R-D10, report_summary.py).

Each draft is a new version, kept in the customer's store and never overwritten; its
SHA-256, its skeleton's SHA-256, who and when go on the project's hash-chained log (R-D4).
The analyst's final may be uploaded back beside it - not required, never read.
"""
from __future__ import annotations

import hashlib
import io
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import (case_flow, case_views, custody, hashchain, intel, projects, report_skeleton,
               report_summary, review, rule_meta, storage)

TZ = timezone(timedelta(hours=7))
THAI_MONTHS = ["", "มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน", "พฤษภาคม", "มิถุนายน", "กรกฎาคม",
               "สิงหาคม", "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม"]
IMAGE_MAX = 8 * 1024 * 1024
FINAL_MAX = 100 * 1024 * 1024
FINAL_TYPES = {".docx": b"PK\x03\x04", ".pdf": b"%PDF-"}
LEVEL_TH = {"critical": "วิกฤต", "high": "สูง", "medium": "กลาง", "low": "ต่ำ", "informational": "ข้อมูล"}
DECISION_TH = {review.ACCEPTED: "ยืนยัน", review.MODIFIED: "ยืนยัน (แก้ไข)", review.REJECTED: "ปฏิเสธ"}
REASON_TH = {"insufficient_evidence": "หลักฐานไม่พอ", "misinterpretation": "ตีความผิด",
             "better_technique": "มีเทคนิคที่ตรงกว่า", "other": "อื่น ๆ"}


class NotReady(Exception):
    """The project's gate is closed; the message says why."""


class BadInput(Exception):
    """A picture or a final the request carries is refused; the message says why."""


# ---------------------------------------------------------------- where things are
def directory(company_id: str, project_id: str) -> Path:
    if not storage.valid_project_id(project_id):
        raise ValueError("bad project id")
    return storage.customer_dir(company_id) / "reports" / project_id


def _entries(company_id: str, project_id: str) -> list[dict]:
    p = storage.project_log_path(company_id, project_id)
    return hashchain.entries(p) if p.exists() else []


def drafts(company_id: str, project_id: str) -> list[dict]:
    return [e for e in _entries(company_id, project_id) if e.get("action") == "report_draft"]


def finals(company_id: str, project_id: str) -> list[dict]:
    return [e for e in _entries(company_id, project_id) if e.get("action") == "report_final"]


def file_path(company_id: str, project_id: str, name: str) -> Path:
    if not re.fullmatch(r"\d+\.\d+-(draft\.docx|final(-\d+)?\.(docx|pdf))", name or ""):
        raise ValueError("bad report file name")
    return directory(company_id, project_id) / name


# ---------------------------------------------------------------- formatting
def _local(ts: str | None) -> str:
    """Any recorded time as GMT+7 'YYYY-MM-DD HH:MM:SS' (event times already are)."""
    if not ts:
        return "-"
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return ts[:19]
    if d.tzinfo is None:
        return d.strftime("%Y-%m-%d %H:%M:%S")
    return d.astimezone(TZ).strftime("%Y-%m-%d %H:%M:%S")


def _date_be(d: datetime, full: bool = False) -> str:
    y = d.year + 543
    return f"{d.day:02d}/{d.month:02d}/{y}" if full else f"{d.day:02d}/{d.month:02d}/{y % 100:02d}"


def _size(n: int | None) -> str:
    if not n:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return str(n)


def _dwell(first: str | None, last: str | None) -> str:
    try:
        a = datetime.fromisoformat(first)
        b = datetime.fromisoformat(last)
    except (TypeError, ValueError):
        return "-"
    s = int((b - a).total_seconds())
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    parts = ([f"{d} วัน"] if d else []) + ([f"{h} ชั่วโมง"] if h else []) + [f"{m} นาที"]
    return " ".join(parts)


def question_text(project: dict | None) -> str:
    """The investigation's question as text - a project keeps it as a record of
    question, window and leads (investigation.py)."""
    q = (project or {}).get("question")
    return ((q.get("question") if isinstance(q, dict) else q) or "").strip()


def _entity(f: dict) -> str:
    return " / ".join(x for x in (f.get("srcip"), f.get("username")) if x) or "-"


def _title(rid: str) -> str:
    try:
        return rule_meta.describe(rid)["title"]
    except KeyError:
        return rid


# ---------------------------------------------------------------- the gate
def gate(company_id: str, project_id: str) -> dict:
    """{open, reasons, undecided, confirmed} - R-D2."""
    project = storage.load_project(company_id, project_id)
    if project is None:
        raise LookupError(project_id)
    t = projects.timeline(company_id, project_id)
    reasons = []
    if not t["cases"]:
        reasons.append("the project holds no processed case")
    if t["undecided"]:
        reasons.append(f"{t['undecided']} suggestion(s) not decided")
    if not question_text(project):
        reasons.append("the investigation's question is not written")
    if report_skeleton.current() is None:
        reasons.append("no report skeleton uploaded (Settings)")
    return {"open": not reasons, "reasons": reasons, "undecided": t["undecided"],
            "confirmed": len(t["findings"])}


# ---------------------------------------------------------------- the context
def context(company_id: str, project_id: str, actor: dict, people: dict, version: str,
            details: str, now: datetime, summary: dict) -> dict:
    project = storage.load_project(company_id, project_id)
    company = storage.load_company(company_id) or {}
    t = projects.timeline(company_id, project_id)
    g = projects.graph(company_id, project_id)
    groups = t["findings"]
    cases = [m for m in storage.list_manifests(company_id) if m.get("project_id") == project_id
             and m.get("status") == "ready"]
    refs = {f["key"] + "|" + f["case_id"]: f"F{n}" for n, f in enumerate(groups, 1)}

    # Executive Summary + its figures
    exec_summary = [f"{p['text']} [{', '.join(p['refs'])}]" for p in summary.get("paragraphs") or []]
    for w in summary.get("warnings") or []:
        exec_summary.append(f"[ระบบตัดย่อหน้านี้ออก เพราะ {'; '.join(w['problems'])} - ข้อความเดิม: {w.get('text')}]")
    if summary.get("error"):
        exec_summary.append(f"[AI ร่างไม่ได้ ({summary['error']}) - ผู้วิเคราะห์ต้องเขียนเอง]")
    firsts = [f["ts_first"] for f in groups if f.get("ts_first")]
    lasts = [f.get("ts_last") or f.get("ts_first") for f in groups if f.get("ts_first")]
    first, last = (min(firsts), max(lasts)) if firsts else (None, None)
    reached = {ta for f in groups for ta in rule_meta.tactics_of(f.get("mitre"))}
    tactics = ", ".join(n for tid, _ta, n in rule_meta.TACTIC_ORDER if tid in reached) or "-"
    suggestions = sum(len(case_views.findings_view(m["case_id"], m, assign_ids=False)) for m in cases)

    # Evidence
    evidence, all_first, all_last = [], [], []
    for m in cases:
        ev = m.get("evidence") or {}
        periods = {p.get("item"): p for p in m.get("periods") or []}
        verified = next((e.get("ts") for e in reversed(custody.entries(m["case_id"]))
                         if e.get("action") in ("verified", "processed")), None)
        members = m.get("members") or [{"name": m.get("original_filename"), "bytes": m.get("uncompressed_bytes")
                                        or m.get("size_bytes"), "rows": m.get("total_rows"),
                                        "mapping": m.get("mapping") or {}}]
        for mem in members:
            p = periods.get(mem.get("name")) or (next(iter(periods.values())) if len(periods) == 1 else {})
            if p.get("first"):
                all_first.append(p["first"])
            if p.get("last"):
                all_last.append(p["last"])
            gaps = p.get("gap_days") or 0
            evidence.append({
                "name": mem.get("name") if len(members) == 1 and mem.get("name") == m.get("original_filename")
                else f"{mem.get('name')} (ใน {m.get('original_filename')})",
                "product": p.get("product") or ", ".join(m.get("products") or []) or "-",
                "first": (p.get("first") or "-")[:19], "last": (p.get("last") or "-")[:19],
                "silent_days": f"{gaps} วัน" if gaps else "-",
                "size": _size(mem.get("bytes")), "sha256": ev.get("sha256") or "-",
                "sha256_short": (ev.get("sha256") or "-")[:16],
                "read_as": ((mem.get("mapping") or {}).get("name")) or "ไม่ได้อ่าน (เก็บเป็นหลักฐาน)",
                "rows_read": f"{mem.get('rows') or 0:,}",
                "rows_not_read": f"{((mem.get('mapping') or {}).get('coverage') or {}).get('not_loaded') or 0:,}",
                "verified": _local(verified), "received": _local(ev.get("recorded_at")),
                "received_by": ev.get("recorded_by") or "-",
            })

    # Standards (the case flow's, each once) and the reproducibility record
    used: dict[str, list[str]] = {}
    for step in case_flow.STEPS:
        for s in step["standards"]:
            used.setdefault(f"{s['source']}", []).append(f"{step['title']} ({s['ref']})")
    standards = [{"name": n, "used_for": "; ".join(v)} for n, v in used.items()]
    sigma_commits = sorted({((m.get("sigma") or {}).get("provenance") or {}).get("commit") for m in cases} - {None})
    feeds = []
    if intel.intel_dir().exists():
        for p in sorted(intel.intel_dir().iterdir()):
            if p.is_file() and p.suffix in intel.FEED_SUFFIXES:
                feeds.append(f"{p.name} ({hashlib.sha256(p.read_bytes()).hexdigest()[:16]})")
    tools = [
        {"name": "Forensic Analyzer", "value": "รุ่นของโปรแกรมยังไม่ถูกบันทึก (ดูหัวข้อ 8)"},
        {"name": "SigmaHQ rules", "value": ", ".join(f"commit {c}" for c in sigma_commits) or "ไม่ได้ใช้"},
        {"name": "Threat intelligence feeds", "value": "; ".join(feeds) or "ไม่มี"},
        {"name": "AI (ร่างบทสรุปผู้บริหาร, อธิบายข้อเสนอ - ไม่ตัดสิน)", "value": summary.get("model") or "-"},
    ]

    # Attack timeline, path, findings
    timeline = []
    confirmed = []
    for n, f in enumerate(groups, 1):
        ref = f"F{n}"
        ta = rule_meta.tactics_of(f.get("mitre"))
        names = {tid: name for tid, _x, name in rule_meta.TACTIC_ORDER}
        timeline.append({"ref": ref, "time": (f.get("ts_first") or "-")[:19],
                         "tactic": ", ".join(names.get(x, x) for x in ta) or "-",
                         "finding": f"{f.get('fd') + ' ' if f.get('fd') else ''}{_title(f['rid'])}",
                         "src": f.get("srcip") or "-", "dst": "-", "account": f.get("username") or "-",
                         "events": f"{f.get('cnt') or 0:,}"})
        rv = f.get("review") or {}
        confirmed.append({"ref": ref, "fd": f.get("fd") or "-", "rule": f"{f['rid']} {_title(f['rid'])}",
                          "level": LEVEL_TH.get(f.get("level"), f.get("level") or "-"), "entity": _entity(f),
                          "first": (f.get("ts_first") or "-")[11:19], "last": (f.get("ts_last") or "-")[11:19],
                          "events": f"{f.get('cnt') or 0:,}",
                          "admiralty": (f.get("admiralty") or {}).get("code") or "-",
                          "note": DECISION_TH.get(rv.get("status"), rv.get("status") or "-")
                          + (f" - {rv.get('note')}" if rv.get("note") else "")})
    edges = [{"src": e.get("from") or "-", "dst": e.get("to") or "-",
              "technique": ", ".join(e.get("mitre") or []) or "-",
              "accounts": ", ".join(e.get("accounts") or []) or "-", "events": f"{e.get('count') or 0:,}"}
             for e in g["graph"]["edges"]]

    rejected, decisions, rules = [], [], {}
    for m in cases:
        for f in case_views.findings_view(m["case_id"], m, assign_ids=False):
            rv = f.get("review") or {}
            if rv.get("status") == review.REJECTED:
                rejected.append({"fd": f.get("fd") or "-", "rule": f"{f['rid']} {_title(f['rid'])}",
                                 "entity": _entity(f),
                                 "reason": REASON_TH.get(rv.get("reason_code"), rv.get("reason_code") or "-")
                                 + (f" - {rv.get('note')}" if rv.get("note") else "")})
        fd_of = {f["key"]: f.get("fd") for f in case_views.findings_view(m["case_id"], m, assign_ids=False)}
        for e in review.log(m["case_id"]):
            if e.get("kind") != "review":
                continue
            decisions.append({"time": _local(e.get("ts")), "actor": e.get("actor") or "-",
                              "fd": fd_of.get(e.get("finding_key")) or e.get("finding_key", "")[:60],
                              "decision": DECISION_TH.get(e.get("status"), e.get("status") or "-"),
                              "reason": REASON_TH.get(e.get("reason_code"), e.get("reason_code") or "")
                              + (f" - {e.get('note')}" if e.get("note") else "")})
    for f in groups:
        if f["rid"] not in rules:
            try:
                d = rule_meta.describe(f["rid"])
            except KeyError:
                d = {"title": f["rid"], "level": f.get("level"), "techniques": f.get("mitre") or []}
            origin = rule_meta.RULE_META.get(f["rid"], {}).get("origin")
            rules[f["rid"]] = {"id": f["rid"], "title": d.get("title") or f["rid"],
                               "level": LEVEL_TH.get(d.get("level"), d.get("level") or "-"),
                               "source": f"SigmaHQ ({d.get('author') or 'author not named'})"
                               if origin == "SigmaHQ" else "in-house",
                               "techniques": ", ".join(d.get("techniques") or f.get("mitre") or []) or "-"}

    # Limitations (ACPO 6.3, 6.5.3) and what better logging would have shown
    limitations, logging = [], []
    for m in cases:
        for s in m.get("skipped_members") or []:
            name = s.get("name") if isinstance(s, dict) else s
            why = s.get("reason") if isinstance(s, dict) else None
            limitations.append(f"{name} (ใน {m.get('original_filename')}) ไม่ได้วิเคราะห์" + (f": {why}" if why else ""))
        for p in m.get("periods") or []:
            if p.get("gap_days"):
                limitations.append(f"{p.get('item')}: ไม่มีเหตุการณ์ {p['gap_days']} วันในช่วงที่หลักฐานครอบคลุม")
            if p.get("rows_without_time"):
                limitations.append(f"{p.get('item')}: {p['rows_without_time']:,} เหตุการณ์ไม่มีเวลาที่อ่านได้")
        for ta in m.get("time_applied") or []:
            if not ta.get("zone") and ta.get("rows_without_offset"):
                limitations.append(f"{ta.get('item')}: เวลาในล็อกไม่ระบุเขตเวลา ถือเป็น GMT+7 "
                                   f"({ta['rows_without_offset']:,} เหตุการณ์)")
        for prod in m.get("detection") or []:
            for a in prod.get("areas") or []:
                if a.get("status") == "n/a":
                    limitations.append(f"{prod.get('name')} - {a.get('name')}: ไม่มีกฎตรวจจับ ({a.get('reason')})")
                    logging.append(f"{prod.get('name')} - {a.get('name')}: {a.get('reason')}")
    limitations.append("รุ่นของโปรแกรมวิเคราะห์ยังไม่ถูกบันทึกในห่วงโซ่การครอบครอง จึงระบุได้เฉพาะรุ่นของกฎ SigmaHQ "
                       "และ AI model")
    limitations.append("ยังไม่มีการบันทึกสมมติฐานทางเลือกและช่วงที่ไม่มีหลักฐานระหว่างขั้นการโจมตีในระบบ "
                       "- ผู้วิเคราะห์ต้องเขียนในหัวข้อ 5")
    limitations = list(dict.fromkeys(limitations))
    recommendations = []
    for m in cases:
        a = storage.load_analysis(m["case_id"]) or {}
        recommendations += [r for r in a.get("recommendations") or [] if isinstance(r, str)]
    recommendations = list(dict.fromkeys(recommendations))

    versions = [{"date_be": _date_be(datetime.fromisoformat(e["ts"]).astimezone(TZ), full=True),
                 "editor": e.get("actor_name") or e.get("actor"), "version": e.get("version"),
                 "details": e.get("details") or ""} for e in drafts(company_id, project_id)]
    versions.append({"date_be": _date_be(now, full=True), "editor": actor.get("name") or actor["email"],
                     "version": version, "details": details or "ฉบับร่างจากระบบ"})
    blank = {"name": "", "position": ""}
    return {
        "customer": company.get("name") or company_id, "project": project.get("name") or project_id,
        "version": version, "date_be": _date_be(now), "versions": versions,
        "author": {"name": actor.get("name") or actor["email"], "position": people.get("author_position") or ""},
        "approver": {"name": people.get("approver_name") or "", "position": people.get("approver_position") or ""}
        if people.get("approver_name") else blank,
        "coordinator": {"name": people.get("coordinator_name") or "",
                        "position": people.get("coordinator_position") or ""}
        if people.get("coordinator_name") else blank,
        "ai_model": summary.get("model") or "-", "exec_summary": exec_summary,
        "question": question_text(project) or "-",
        "first_confirmed": (first or "-")[:19], "last_confirmed": (last or "-")[:19], "dwell": _dwell(first, last),
        "confirmed_count": str(len(groups)), "suggestion_count": str(suggestions), "tactics": tactics,
        "period_from": (min(all_first) if all_first else "-")[:19], "period_to": (max(all_last) if all_last else "-")[:19],
        "evidence_count": str(len(evidence)), "case_count": str(len(cases)), "evidence": evidence,
        "standards": standards, "tools": tools, "attack_timeline": timeline, "edges": edges,
        "confirmed": confirmed, "rejected": rejected, "limitations": limitations,
        "recommendations": recommendations, "logging_improvements": list(dict.fromkeys(logging)),
        "rules": list(rules.values()), "decisions": decisions,
        "_refs": refs,
    }


# ---------------------------------------------------------------- pictures
_PNG = b"\x89PNG\r\n\x1a\n"


def check_png(data: bytes | None) -> None:
    if not data:
        return
    if len(data) > IMAGE_MAX or not data.startswith(_PNG):
        raise BadInput("the attack path picture is not a PNG (or is over 8 MB)")
    # A PNG header over a broken body passed the check above and crashed the render
    # (500) - measured in tests/check_report.py. Parse it as Word's writer will.
    from docx.image.image import Image
    try:
        Image.from_blob(data)
    except Exception:
        raise BadInput("the attack path picture is not a readable PNG") from None


def check_svg(data: bytes | None) -> None:
    """An SVG goes into the Word file as it is: nothing in it may run or load."""
    if not data:
        return
    if len(data) > IMAGE_MAX:
        raise BadInput("the attack path SVG is over 8 MB")
    head = data[:2000].lstrip().lower()
    if not (head.startswith(b"<svg") or head.startswith(b"<?xml")) or b"<svg" not in data[:4000].lower():
        raise BadInput("the attack path drawing is not an SVG")
    low = data.lower()
    for bad in (b"<script", b"<foreignobject", b"javascript:", b"<!entity", b"<iframe"):
        if bad in low:
            raise BadInput(f"the attack path SVG holds {bad.decode()} - refused")
    if re.search(rb"""(?:href|src)\s*=\s*["'](?!#|data:)""", low) or b"@import" in low \
            or re.search(rb"""url\(\s*["']?(?!#|data:)""", low):
        raise BadInput("the attack path SVG refers to something outside itself - refused")


def _attach_svg(doc_bytes: bytes, png_sha: str, svg: bytes) -> bytes:
    """Give the inserted PNG an SVG twin, the way Word stores one (asvg:svgBlip): Word 2016+
    shows the SVG, older Word and LibreOffice the PNG (R-D9)."""
    from docx import Document
    from docx.opc.constants import RELATIONSHIP_TYPE as RT
    from docx.opc.packuri import PackURI
    from docx.opc.part import Part

    doc = Document(io.BytesIO(doc_bytes))
    part = doc.part
    target = None
    for rid, rel in part.rels.items():
        if rel.reltype == RT.IMAGE and not rel.is_external \
                and hashlib.sha256(rel.target_part.blob).hexdigest() == png_sha:
            target = rid
    if target is None:
        return doc_bytes
    n = 1 + sum(1 for p in part.package.iter_parts() if str(p.partname).startswith("/word/media/"))
    svg_part = Part(PackURI(f"/word/media/attack_path_{n}.svg"), "image/svg+xml", svg, part.package)
    svg_rid = part.relate_to(svg_part, RT.IMAGE)
    A = "http://schemas.openxmlformats.org/drawingml/2006/main"
    R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    ASVG = "http://schemas.microsoft.com/office/drawing/2016/SVG/main"
    from lxml import etree
    for blip in part.element.iter(f"{{{A}}}blip"):
        if blip.get(f"{{{R}}}embed") != target:
            continue
        ext_lst = blip.find(f"{{{A}}}extLst")
        if ext_lst is None:
            ext_lst = etree.SubElement(blip, f"{{{A}}}extLst")
        ext = etree.SubElement(ext_lst, f"{{{A}}}ext")
        ext.set("uri", "{96DAC541-7B7A-43D3-8B79-37D633B846F1}")
        sb = etree.SubElement(ext, f"{{{ASVG}}}svgBlip", nsmap={"asvg": ASVG})
        sb.set(f"{{{R}}}embed", svg_rid)
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


# ---------------------------------------------------------------- make a draft
def next_version(company_id: str, project_id: str) -> str:
    n = len(drafts(company_id, project_id))
    return f"0.{n + 1}"


def make_draft(company_id: str, project_id: str, actor: dict, *, details: str = "", people: dict | None = None,
               png: bytes | None = None, svg: bytes | None = None, summarise=None) -> dict:
    """Build, keep and log one draft; returns its log line. Raises NotReady / BadInput."""
    from docx.shared import Mm
    from docxtpl import DocxTemplate, InlineImage

    g = gate(company_id, project_id)
    if not g["open"]:
        raise NotReady("; ".join(g["reasons"]))
    check_png(png)
    check_svg(svg)
    if svg and not png:
        raise BadInput("an SVG needs its PNG beside it (older Word and LibreOffice show the PNG)")
    skeleton = report_skeleton.current()
    project = storage.load_project(company_id, project_id)
    t = projects.timeline(company_id, project_id)
    gr = projects.graph(company_id, project_id)
    summary = (summarise or report_summary.draft)(question_text(project), t["findings"], gr["graph"]["edges"])
    now = datetime.now(TZ)
    version = next_version(company_id, project_id)
    ctx = context(company_id, project_id, actor, people or {}, version, details, now, summary)
    ctx.pop("_refs", None)
    tpl = DocxTemplate(str(report_skeleton.path(skeleton["sha256"])))
    ctx["attack_path_image"] = (InlineImage(tpl, io.BytesIO(png), width=Mm(160)) if png else
                                "[ไม่ได้แนบภาพเส้นทางการโจมตี - ผู้วิเคราะห์ใส่เองได้จากหน้า Attack path]")
    tpl.render(ctx)
    buf = io.BytesIO()
    tpl.save(buf)
    data = buf.getvalue()
    if svg and png:
        data = _attach_svg(data, hashlib.sha256(png).hexdigest(), svg)
    sha = hashlib.sha256(data).hexdigest()
    name = f"{version}-draft.docx"
    with storage.PROJECT_LOCK:
        if next_version(company_id, project_id) != version:   # another draft won the race
            raise NotReady("another draft was made at the same time - make it again")
        d = directory(company_id, project_id)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / (name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(d / name)
        return hashchain.append(storage.project_log_path(company_id, project_id), {
            "action": "report_draft", "actor": actor["email"], "actor_name": actor.get("name"),
            "version": version, "file": name, "sha256": sha, "bytes": len(data),
            "skeleton_sha256": skeleton["sha256"], "details": (details or "")[:500],
            "confirmed": len(t["findings"]),
            "attack_path_png_sha256": hashlib.sha256(png).hexdigest() if png else None,
            "attack_path_svg_sha256": hashlib.sha256(svg).hexdigest() if svg else None,
            "summary": {"model": summary.get("model"), "kept": len(summary.get("paragraphs") or []),
                        "refused": len(summary.get("warnings") or []), "error": summary.get("error"),
                        "seconds": summary.get("seconds")},
        })


def add_final(company_id: str, project_id: str, actor: dict, filename: str, data: bytes, version: str) -> dict:
    """Keep the analyst's final beside the drafts (R-D4): never read, never required."""
    if storage.load_project(company_id, project_id) is None:
        raise LookupError(project_id)
    ext = Path(filename or "").suffix.lower()
    if ext not in FINAL_TYPES or not data.startswith(FINAL_TYPES[ext]):
        raise BadInput("a final is a .docx or a .pdf")
    if len(data) > FINAL_MAX:
        raise BadInput("a final is at most 100 MB")
    if version not in {e.get("version") for e in drafts(company_id, project_id)}:
        raise BadInput(f"no draft {version} in this project")
    sha = hashlib.sha256(data).hexdigest()
    with storage.PROJECT_LOCK:
        d = directory(company_id, project_id)
        d.mkdir(parents=True, exist_ok=True)
        n = sum(1 for e in finals(company_id, project_id) if e.get("version") == version)
        name = f"{version}-final{'' if n == 0 else f'-{n + 1}'}{ext}"
        tmp = d / (name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(d / name)
        return hashchain.append(storage.project_log_path(company_id, project_id), {
            "action": "report_final", "actor": actor["email"], "version": version, "file": name,
            "original_name": (filename or "")[:200], "sha256": sha, "bytes": len(data),
        })


def listing(company_id: str, project_id: str) -> dict:
    """The Report section of a project: the gate, every draft and final with its digest."""
    d = drafts(company_id, project_id)
    f = finals(company_id, project_id)
    return {"gate": gate(company_id, project_id),
            "next_version": next_version(company_id, project_id),
            "skeleton": report_skeleton.current(),
            "drafts": [{k: e.get(k) for k in ("ts", "actor", "actor_name", "version", "file", "sha256", "bytes",
                                                "skeleton_sha256", "details", "summary")} for e in d],
            "finals": [{k: e.get(k) for k in ("ts", "actor", "version", "file", "original_name", "sha256", "bytes")}
                       for e in f]}
