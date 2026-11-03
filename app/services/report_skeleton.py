"""The report skeleton: the provider's Word layout the drafts are filled into (specs/forensic_report.md R-D11).

Uploaded by an administrator on the Settings page, never committed (it carries the provider's
letterhead and the repository is pushed). Kept in the shared part of DATA_DIR - provider
configuration, no customer's data - every version as `<sha256>.docx`, each upload a
hash-chained line of `report/log.jsonl`. The newest is the one used; a draft's log line names
the skeleton it was built from, so a draft can be rebuilt (ACPO principle 3).

A skeleton is refused, with every reason named, when it is not a .docx, too big, misses a
required tag or uses one the drafts do not fill, holds a tag that does not parse, links
anything outside the file (an INCLUDEPICTURE field fetched another organisation's logos
into the first skeleton - specs/forensic_report.md "The .docx"), or fails a test render.
"""
from __future__ import annotations

import hashlib
import io
import re
import threading
import zipfile
from pathlib import Path

from .. import config
from . import hashchain

MAX_BYTES = 20 * 1024 * 1024
LOCK = threading.Lock()

# Every top-level tag a draft fills, with what it holds - the Settings page lists them.
TAGS: dict[str, str] = {
    "customer": "the customer's name",
    "project": "the investigation (project) name",
    "version": "the draft's version, 0.1 first",
    "date_be": "the draft's date, dd/mm/yy in the Buddhist era",
    "versions": "rows: every draft made (v.date_be, v.editor, v.version, v.details)",
    "author": "author.name, author.position - the account making the draft",
    "approver": "approver.name, approver.position - chosen on the draft form, may be blank",
    "coordinator": "coordinator.name, coordinator.position - chosen on the draft form, may be blank",
    "ai_model": "the model that drafted the Executive Summary",
    "exec_summary": "paragraphs: the AI's draft of the Executive Summary, each ending with its [F..] citations",
    "question": "the investigation's question",
    "first_confirmed": "the first confirmed event, GMT+7",
    "last_confirmed": "the last confirmed event, GMT+7",
    "dwell": "time from the first to the last confirmed event",
    "confirmed_count": "confirmed groups",
    "suggestion_count": "suggestions the system made",
    "tactics": "ATT&CK tactics the confirmed groups reach, in ATT&CK's order",
    "period_from": "the first event of all evidence",
    "period_to": "the last event of all evidence",
    "evidence_count": "evidence files",
    "case_count": "cases (uploads) in the project",
    "evidence": "rows: e.name, e.product, e.first, e.last, e.silent_days, e.size, e.sha256, "
                "e.sha256_short, e.read_as, e.rows_read, e.rows_not_read, e.verified, e.received, e.received_by",
    "standards": "rows: s.name, s.used_for",
    "tools": "rows: t.name, t.value - the reproducibility record",
    "attack_timeline": "rows: s.ref, s.time, s.tactic, s.finding, s.src, s.dst, s.account, s.events",
    "attack_path_image": "the attack path picture",
    "edges": "rows: x.src, x.dst, x.technique, x.accounts, x.events",
    "confirmed": "rows: f.ref, f.fd, f.rule, f.level, f.entity, f.first, f.last, f.events, f.admiralty, f.note",
    "rejected": "rows: f.fd, f.rule, f.entity, f.reason",
    "limitations": "items: what the evidence and the analysis cannot show",
    "recommendations": "items: the AI narrative's recommendations, a starting draft",
    "logging_improvements": "items: logging that would have shown more",
    "rules": "rows: r.id, r.title, r.level, r.source, r.techniques",
    "decisions": "rows: d.time, d.actor, d.fd, d.decision, d.reason",
}
# A skeleton without these cannot be a draft of this report.
REQUIRED = ("customer", "project", "version", "date_be", "versions", "exec_summary",
            "attack_path_image", "confirmed")

_LINKED_FIELD = re.compile(rb"\b(INCLUDEPICTURE|INCLUDETEXT|LINK|DDEAUTO|DDE|IMPORT)\b")
_EXTERNAL_REL = re.compile(rb"<Relationship\b[^>]*TargetMode=\"External\"[^>]*>")
_HYPERLINK = b"/relationships/hyperlink\""


def directory() -> Path:
    return Path(config.DATA_DIR) / "report"


def log_path() -> Path:
    return directory() / "log.jsonl"


def path(sha256: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", sha256 or ""):
        raise ValueError("not a SHA-256")
    return directory() / f"{sha256}.docx"


def history() -> list[dict]:
    p = log_path()
    return [e for e in hashchain.entries(p) if e.get("action") == "skeleton_uploaded"] if p.exists() else []


def current() -> dict | None:
    """The skeleton drafts are made from: the newest upload whose file is there."""
    for e in reversed(history()):
        if path(e["sha256"]).exists():
            return e
    return None


def sample_context(template) -> dict:
    """Invented values for the test render - no customer's data."""
    from docx.shared import Mm  # noqa: F401  (imported where docxtpl is)
    row = {k: "x" for k in ("date_be", "editor", "version", "details", "name", "position", "product",
                            "first", "last", "silent_days", "size", "sha256", "sha256_short", "read_as",
                            "rows_read", "rows_not_read", "verified", "received", "received_by",
                            "used_for", "value", "ref", "time", "tactic", "finding", "src", "dst",
                            "account", "events", "technique", "accounts", "fd", "rule", "level",
                            "entity", "admiralty", "note", "reason", "id", "title", "source",
                            "techniques", "actor", "decision")}
    ctx = {k: "x" for k in TAGS}
    for k in ("versions", "evidence", "standards", "tools", "attack_timeline", "edges", "confirmed",
              "rejected", "rules", "decisions"):
        ctx[k] = [row]
    for k in ("exec_summary", "limitations", "recommendations", "logging_improvements"):
        ctx[k] = ["x"]
    for k in ("author", "approver", "coordinator"):
        ctx[k] = {"name": "x", "position": "x"}
    ctx["attack_path_image"] = ""
    return ctx


def check(data: bytes) -> tuple[list[str], set[str]]:
    """(problems, tags used). No problem = the skeleton may be used."""
    problems: list[str] = []
    if len(data) > MAX_BYTES:
        return [f"larger than {MAX_BYTES // (1024 * 1024)} MB"], set()
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
    except zipfile.BadZipFile:
        return ["not a Word file (.docx)"], set()
    if "word/document.xml" not in names:
        return ["not a Word file (.docx): no word/document.xml"], set()
    for n in sorted(names):
        if n.startswith("word/") and n.endswith(".xml"):
            body = z.read(n)
            for instr in re.findall(rb"<w:instrText[^>]*>([^<]*)<", body) + re.findall(rb'w:instr="([^"]*)"', body):
                m = _LINKED_FIELD.search(instr)
                if m:
                    problems.append(f"{n} has a {m.group(1).decode()} field - it loads something from "
                                    "outside the file when Word updates fields; unlink it (Ctrl+Shift+F9)")
        if n.endswith(".rels"):
            for rel in _EXTERNAL_REL.findall(z.read(n)):
                if _HYPERLINK not in rel:
                    target = re.search(rb'Target="([^"]*)"', rel)
                    problems.append(f"{n} links to {target.group(1).decode(errors='replace') if target else '?'} "
                                    "outside the file")
    try:
        from docxtpl import DocxTemplate
        tpl = DocxTemplate(io.BytesIO(data))
        used = set(tpl.get_undeclared_template_variables())
    except Exception as exc:
        return problems + [f"a tag does not parse: {str(exc)[:300]}"], set()
    missing = [t for t in REQUIRED if t not in used]
    if missing:
        problems.append("missing required tag(s): " + ", ".join(missing))
    unknown = sorted(used - set(TAGS))
    if unknown:
        problems.append("tag(s) no draft fills (a typo?): " + ", ".join(unknown))
    if not problems:
        try:
            tpl = DocxTemplate(io.BytesIO(data))
            tpl.render(sample_context(tpl))
            tpl.save(io.BytesIO())
        except Exception as exc:
            problems.append(f"a test render failed: {str(exc)[:300]}")
    return list(dict.fromkeys(problems)), used


class Refused(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def upload(actor: str, filename: str, data: bytes) -> dict:
    """Check, keep and log a skeleton; it becomes the current one. Raises Refused."""
    problems, used = check(data)
    if problems:
        raise Refused(problems)
    sha = hashlib.sha256(data).hexdigest()
    with LOCK:
        directory().mkdir(parents=True, exist_ok=True)
        target = path(sha)
        if not target.exists():
            tmp = target.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(target)
        return hashchain.append(log_path(), {
            "action": "skeleton_uploaded", "actor": actor, "sha256": sha,
            "file": (filename or "")[:200], "bytes": len(data), "tags": sorted(used),
        })
