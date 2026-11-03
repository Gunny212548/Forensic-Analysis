"""The forensic report draft (specs/forensic_report.md, IAI-72 / IAI-73).

    python tests/check_report.py [repo dir] [--scratch DIR]

A throwaway DATA_DIR and AUTH_DIR, the real app through FastAPI's TestClient. The skeleton is
built here with python-docx (the provider's own is never in git), the AI is a stand-in - no
Ollama - and cases are made in storage with findings written straight into their DuckDB.
"""
import argparse
import hashlib
import io
import os
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("repo", nargs="?", default=str(Path(__file__).resolve().parents[1]))
ap.add_argument("--scratch", default=None)
args = ap.parse_args()
scratch = Path(args.scratch or tempfile.mkdtemp(prefix="report-"))
shutil.rmtree(scratch, ignore_errors=True)
(scratch / "data").mkdir(parents=True)
(scratch / "auth").mkdir(parents=True)
os.environ["DATA_DIR"] = str(scratch / "data")
os.environ["AUTH_DIR"] = str(scratch / "auth")
os.environ["TRIAGE_ENABLED"] = "0"
sys.path.insert(0, args.repo)

from docx import Document  # noqa: E402
from docx.opc.constants import RELATIONSHIP_TYPE as RT  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.services import (auth, authz, db, hashchain, investigation, report, report_skeleton,  # noqa: E402
                          report_summary, storage)

failures = 0


def check(name: str, ok: bool) -> None:
    global failures
    print(("  ok   " if ok else "  FAIL ") + name)
    failures += 0 if ok else 1


PW = "correct horse battery"
for email, role in (("admin@x.test", authz.ADMIN), ("manager@x.test", authz.MANAGER),
                    ("analyst@x.test", authz.ANALYST)):
    auth.create_account("check", email, role.title() + " Person", role, PW)

from app.main import app  # noqa: E402


def client(email: str) -> TestClient:
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"email": email, "password": PW}).status_code == 200
    return c


admin, manager, analyst = client("admin@x.test"), client("manager@x.test"), client("analyst@x.test")


# ---------------------------------------------------------------- a skeleton built here
LOOPS = {
    "versions": ("v", "{{ v.version }} | {{ v.editor }} | {{ v.date_be }} | {{ v.details }}"),
    "evidence": ("e", "{{ e.name }} | {{ e.sha256 }} | {{ e.read_as }} | {{ e.rows_read }} | {{ e.first }}"),
    "standards": ("s", "{{ s.name }} | {{ s.used_for }}"),
    "tools": ("t", "{{ t.name }} | {{ t.value }}"),
    "attack_timeline": ("s", "{{ s.ref }} | {{ s.time }} | {{ s.finding }} | {{ s.src }}"),
    "edges": ("x", "{{ x.src }} -> {{ x.dst }} | {{ x.technique }}"),
    "confirmed": ("f", "CONF {{ f.ref }} | {{ f.rule }} | {{ f.entity }} | {{ f.note }}"),
    "rejected": ("f", "REJ {{ f.rule }} | {{ f.entity }} | {{ f.reason }}"),
    "rules": ("r", "{{ r.id }} | {{ r.title }} | {{ r.source }}"),
    "decisions": ("d", "{{ d.actor }} | {{ d.decision }} | {{ d.reason }}"),
}
ITEMS = ("exec_summary", "limitations", "recommendations", "logging_improvements")
SCALARS = [t for t in report_skeleton.TAGS if t not in LOOPS and t not in ITEMS
           and t not in ("author", "approver", "coordinator", "attack_path_image")]


def skeleton(drop: str | None = None, extra: str = "", field: str | None = None,
             external: str | None = None) -> bytes:
    d = Document()
    for t in SCALARS:
        d.add_paragraph(f"{t}: {{{{ {t} }}}}")
    for who in ("author", "approver", "coordinator"):
        d.add_paragraph(f"{who}: {{{{ {who}.name }}}} / {{{{ {who}.position }}}}")
    for name in ITEMS:
        if name == drop:
            continue
        d.add_paragraph(f"{{%p for x in {name} %}}")
        d.add_paragraph(f"{name.upper()}: {{{{ x }}}}")
        d.add_paragraph("{%p endfor %}")
    for name, (var, row) in LOOPS.items():
        if name == drop:
            continue
        tbl = d.add_table(rows=3, cols=1)
        tbl.cell(0, 0).text = f"{{%tr for {var} in {name} %}}"
        tbl.cell(1, 0).text = row
        tbl.cell(2, 0).text = "{%tr endfor %}"
    if drop != "attack_path_image":
        d.add_paragraph("{{ attack_path_image }}")
    if extra:
        d.add_paragraph(extra)
    if field:
        from docx.oxml.ns import qn
        from lxml import etree
        fld = etree.SubElement(d.add_paragraph()._p, qn("w:fldSimple"))
        fld.set(qn("w:instr"), field)
        etree.SubElement(etree.SubElement(fld, qn("w:r")), qn("w:t")).text = "x"
    if external:
        d.part.relate_to(external[1], external[0], is_external=True)
    out = io.BytesIO()
    d.save(out)
    return out.getvalue()


def put_skeleton(c: TestClient, data: bytes, name: str = "skel.docx"):
    return c.post("/api/settings/report-skeleton",
                  files={"file": (name, io.BytesIO(data), "application/octet-stream")})


# ---------------------------------------------------------------- cases
co = storage.create_company("Acme Holdings")
CO = co["company_id"]
other = storage.create_company("Zebra Unrelated Ltd")


def case(company_id: str, project: dict, rows: list[tuple]) -> str:
    """A ready case; rows = (rid, ts, srcip, username)."""
    cid = storage.create_case("evidence.log", "log", 1, company_id=company_id, project=project)["case_id"]
    con = db.init(cid)
    for i, (rid, ts, src, user) in enumerate(rows):
        con.execute("INSERT INTO raw_events (row_id, ts, srcip, username) VALUES (?, ?, ?, ?)", [i, ts, src, user])
        con.execute("INSERT INTO findings (row_id, rid, lvl, descr, mitre) VALUES (?, ?, 3, 'seen', ['T1110'])",
                    [i, rid])
    con.close()
    storage.raw_path(cid, "log").write_text("x\n", encoding="utf-8")
    storage.update_case(cid, status="ready", evidence={"sha256": "ab" * 32, "bytes": 2,
                                                       "recorded_at": "2026-09-20T03:00:00+00:00",
                                                       "recorded_by": "analyst@x.test"})
    return cid


pj = storage.create_project(CO, "RDP intrusion", "check")
PJ = pj["project_id"]
c1 = case(CO, pj, [("R2000", "2026-09-17 02:04:13", "198.51.100.66", "adm.hd"),
                   ("R2008", "2026-09-17 02:30:47", "198.51.100.66", "adm.hd"),
                   ("R3001", "2026-09-17 03:10:00", "10.0.0.9", "")])
zpj = storage.create_project(other["company_id"], "Zebra case", "check")
case(other["company_id"], zpj, [("R2000", "2026-09-01 01:00:00", "203.0.113.250", "zebra.user")])

calls = []


def fake_summary(question, groups, edges):
    calls.append((question, len(groups)))
    return {"paragraphs": [{"text": "สรุปเหตุการณ์ทดสอบ", "refs": ["F1", "F2"]},
                           {"text": "ย่อหน้าที่อ้างกลุ่ม", "refs": ["G1"]}],
            "labels": {"G1": "R2000 ทั้ง 2 รายการ"},
            "warnings": [{"text": "ย่อหน้าที่ผิด", "refs": ["F1"], "problems": ["names the account adm.hu"]}],
            "recommendations": [{"text": "เปลี่ยนรหัสผ่านบัญชี adm.hd", "refs": ["F1", "G1"]}],
            "recommendation_warnings": [{"text": "ข้อเสนอที่ผิด", "refs": ["F2"],
                                         "problems": ["names the address 203.0.113.9, which no cited finding holds"]}],
            "error": None, "model": "stand-in", "seconds": 0.1, "usage": None}


real_draft = report_summary.draft
report_summary.draft = fake_summary   # make_draft resolves it at call time
BASE = f"/api/companies/{CO}/projects/{PJ}/report"


def _png(w: int = 4, h: int = 2) -> bytes:
    """A real PNG, so python-docx can read its size."""
    import struct
    import zlib
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


PNG = _png()
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><circle cx="5" cy="5" r="4"/></svg>'


def text_of(data: bytes) -> str:
    z = zipfile.ZipFile(io.BytesIO(data))
    return " ".join(re.sub(r"<[^>]+>", " ", z.read(n).decode("utf8")) for n in z.namelist()
                    if re.match(r"word/(document|header\d*|footer\d*)\.xml$", n))


print("R-D11: the skeleton is uploaded on Settings, by an administrator")
good = skeleton()
for who, c in (("manager", manager), ("analyst", analyst)):
    check(f"a {who} may not read or upload it (403)",
          c.get("/api/settings/report-skeleton").status_code == 403 and put_skeleton(c, good).status_code == 403)
r = admin.get(f"{BASE}")
check("no skeleton yet: the report gate says so",
      r.status_code == 200 and any("skeleton" in x for x in r.json()["gate"]["reasons"]))
refusals = {
    "not a Word file": b"plain text",
    "missing required tag(s): confirmed": skeleton(drop="confirmed"),
    "missing required tag(s): attack_path_image": skeleton(drop="attack_path_image"),
    "tag(s) no draft fills (a typo?): custmer": skeleton(extra="{{ custmer }}"),
    "a tag does not parse": skeleton(extra="{{ customer "),
    "INCLUDEPICTURE field": skeleton(field='INCLUDEPICTURE "https://example.com/logo.png" \\* MERGEFORMATINET'),
    "outside the file": skeleton(external=(RT.IMAGE, "https://example.com/logo.png")),
}
for why, data in refusals.items():
    r = put_skeleton(admin, data)
    probs = (r.json().get("detail") or {}).get("problems", []) if r.status_code == 400 else []
    check(f"refused, naming '{why}' ({r.status_code})", r.status_code == 400 and any(why in p for p in probs))
check("nothing refused became the skeleton", report_skeleton.current() is None)
r = put_skeleton(admin, skeleton(external=(RT.HYPERLINK, "https://www.example.com/")), "with-link.docx")
check("a hyperlink to a website is allowed (it loads nothing)", r.status_code == 200)
first_sha = r.json()["sha256"]
r = put_skeleton(admin, good, "provider.docx")
check("the administrator uploads a skeleton; it is the current one",
      r.status_code == 200 and report_skeleton.current()["sha256"] == hashlib.sha256(good).hexdigest())
info = admin.get("/api/settings/report-skeleton").json()
check("the history keeps both, newest first; tags and required listed",
      [e["sha256"] for e in info["history"]] == [hashlib.sha256(good).hexdigest(), first_sha]
      and "confirmed" in info["required"] and "exec_summary" in info["tags"])
r = admin.get(f"/api/settings/report-skeleton/{first_sha}")
check("an earlier skeleton is still downloadable",
      r.status_code == 200 and r.content == skeleton(external=(RT.HYPERLINK, "https://www.example.com/")) or
      (r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == first_sha))
check("an unknown or malformed skeleton id is 404",
      admin.get("/api/settings/report-skeleton/" + "0" * 64).status_code == 404
      and admin.get("/api/settings/report-skeleton/..%2Fx").status_code == 404)
check("the skeleton log is hash-chained and intact", hashchain.verify(report_skeleton.log_path())["intact"])

print("R-D2: a draft only once every suggestion is decided - the question is not required")
r = analyst.post(f"{BASE}/draft")
check(f"suggestions not decided: refused (409, {r.status_code})",
      r.status_code == 409 and "not decided" in r.json()["detail"])
keys = [f["key"] for f in db.collapsed_findings(c1)]
for k in keys:
    action = "reject" if k.startswith("R3001") else "accept"
    body = {"finding_key": k, "action": action}
    if action == "reject":
        body.update(reason_code="misinterpretation", note="backup job")
    assert analyst.post(f"/api/cases/{c1}/review", json=body).status_code == 200
gate = analyst.get(BASE).json()["gate"]
check("every suggestion decided, no question written: the gate is open",
      gate["open"] is True and not any("question" in x for x in gate["reasons"]))
investigation.save(c1, {"question": "Who entered RDS01 and where did they go?"}, "manager@x.test")
# A case's AI narrative cached from before (it read suggestions not decided): never in the draft.
storage.save_analysis(c1, {"summary": "x", "recommendations": ["NARRATIVE-RECOMMENDATION"]})
check("the gate stays open once a question is written", analyst.get(BASE).json()["gate"]["open"] is True)

print("R-D0 / R-D3 / R-D10: the draft")
r = analyst.post(f"{BASE}/draft", data={"details": "first draft", "author_position": "Forensic Analyst",
                                        "approver_name": "Manager Person", "approver_position": "Lead"},
                 files={"png": ("g.png", io.BytesIO(PNG), "image/png"), "svg": ("g.svg", io.BytesIO(SVG), "image/svg+xml")})
check(f"an analyst makes a draft (200, {r.status_code})", r.status_code == 200)
line = r.json() if r.status_code == 200 else {}
check("it is version 0.1, a .docx", line.get("version") == "0.1" and line.get("file") == "0.1-draft.docx")
check("the stand-in model got the question and the confirmed groups only (2 of 3)",
      calls and calls[-1] == ("Who entered RDS01 and where did they go?", 2))
dl = analyst.get(f"{BASE}/files/0.1-draft.docx")
data = dl.content
check("the draft downloads, and its SHA-256 is the one on the log",
      dl.status_code == 200 and hashlib.sha256(data).hexdigest() == line.get("sha256"))
txt = text_of(data)
check("customer, project, version and question are filled in",
      all(s in txt for s in ("Acme Holdings", "RDP intrusion", "0.1", "Who entered RDS01")))
check("the AI's paragraph carries its references", "สรุปเหตุการณ์ทดสอบ [F1, F2]" in txt)
check("a G reference reads as its rule and count", "ย่อหน้าที่อ้างกลุ่ม [R2000 ทั้ง 2 รายการ]" in txt)
check("section 9 holds the report AI's recommendation with its references",
      "RECOMMENDATIONS: เปลี่ยนรหัสผ่านบัญชี adm.hd [F1, R2000 ทั้ง 2 รายการ]" in txt)
check("a refused recommendation is shown with its reason in Thai",
      "ระบบตัดข้อเสนอนี้ออก เพราะอ้างถึงหมายเลข IP 203.0.113.9" in txt and "ข้อเสนอที่ผิด" in txt)
check("a case's cached AI narrative is not read into the draft (2026-11-03, the user chose A)",
      "NARRATIVE-RECOMMENDATION" not in txt)
check("a refused paragraph is shown with its reason, in Thai, and its text",
      "อ้างถึงบัญชี adm.hu" in txt and "names the account" not in txt and "ย่อหน้าที่ผิด" in txt)
conf = re.findall(r"CONF F\d+[^|]*\|[^|]*\|", txt)
check("section 7.1 lists the two confirmed groups as F1, F2",
      len(conf) == 2 and "CONF F1" in txt and "CONF F2" in txt)
check("the rejected group is in 7.2 with its reason, not in 7.1",
      re.search(r"REJ R3001[^|]*\| 10\.0\.0\.9 \| ตีความผิด - backup job", txt) is not None
      and "10.0.0.9 | ยืนยัน" not in txt)
check("people: author from the account, approver from the form",
      "Analyst Person / Forensic Analyst" in txt and "Manager Person / Lead" in txt)
check("no other customer's data", "Zebra" not in txt and "203.0.113.250" not in txt and "zebra.user" not in txt)
z = zipfile.ZipFile(io.BytesIO(data))
media = [n for n in z.namelist() if n.startswith("word/media/")]
docxml = z.read("word/document.xml").decode("utf8")
check("the attack path is inserted as a PNG with its SVG twin (asvg:svgBlip)",
      any(n.endswith(".png") for n in media) and any(n.endswith(".svg") for n in media) and "svgBlip" in docxml)
check("nothing in it is protected from editing", b"documentProtection" not in z.read("word/settings.xml"))
check("the draft's log line names its skeleton and pictures",
      line.get("skeleton_sha256") == hashlib.sha256(good).hexdigest()
      and line.get("attack_path_png_sha256") == hashlib.sha256(PNG).hexdigest()
      and line.get("summary", {}).get("refused") == 1
      and line["summary"].get("recommendations") == 1 and line["summary"].get("recommendations_refused") == 1)
check("the log line keeps the cover-page names given, so the page offers them again",
      line.get("people") == {"author_position": "Forensic Analyst", "approver_name": "Manager Person",
                             "approver_position": "Lead"})

r = analyst.post(f"{BASE}/draft", data={"details": "second"})
check("a second draft is 0.2 and keeps 0.1", r.status_code == 200 and r.json()["version"] == "0.2"
      and analyst.get(f"{BASE}/files/0.1-draft.docx").status_code == 200)
txt2 = text_of(analyst.get(f"{BASE}/files/0.2-draft.docx").content)
check("0.2's change log lists both versions with their details",
      "0.1 |" in txt2 and "first draft" in txt2 and "0.2 |" in txt2 and "second" in txt2)
check("without a picture the draft says so", "ไม่ได้แนบภาพเส้นทางการโจมตี" in txt2)

print("Pictures: nothing in them may run or load")
for name, files, why in (
        ("not a PNG", {"png": ("g.png", io.BytesIO(b"GIF89a"), "image/png")}, "PNG"),
        ("a PNG header over a broken body", {"png": ("g.png", io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 40),
                                                     "image/png")}, "readable PNG"),
        ("a script in the SVG", {"png": ("g.png", io.BytesIO(PNG), "image/png"),
                                 "svg": ("g.svg", io.BytesIO(SVG.replace(b"<circle", b"<script>x</script><circle")),
                                         "image/svg+xml")}, "script"),
        ("an outside link in the SVG", {"png": ("g.png", io.BytesIO(PNG), "image/png"),
                                        "svg": ("g.svg", io.BytesIO(SVG.replace(b"<circle", b'<image href="https://x/y.png"/><circle')),
                                                "image/svg+xml")}, "outside"),
        ("a style that imports from outside", {"png": ("g.png", io.BytesIO(PNG), "image/png"),
                                               "svg": ("g.svg", io.BytesIO(SVG.replace(
                                                   b"<circle", b"<style>@import url(https://x/y.css);</style><circle")),
                                                   "image/svg+xml")}, "outside"),
        ("a fill from another site", {"png": ("g.png", io.BytesIO(PNG), "image/png"),
                                      "svg": ("g.svg", io.BytesIO(SVG.replace(
                                          b"<circle", b'<circle fill="url(https://x/p.svg#g)"/><circle')),
                                          "image/svg+xml")}, "outside"),
        ("an SVG without its PNG", {"svg": ("g.svg", io.BytesIO(SVG), "image/svg+xml")}, "PNG")):
    r = analyst.post(f"{BASE}/draft", files=files)
    check(f"{name}: refused (400, {r.status_code})", r.status_code == 400 and why in r.json()["detail"])
check("a refused request made no draft", len(report.drafts(CO, PJ)) == 2)

print("R-D4: the analyst's final may be uploaded back")
PDF = b"%PDF-1.7\n" + b"x" * 100
r = analyst.post(f"{BASE}/final", data={"version": "0.1"}, files={"file": ("final.pdf", io.BytesIO(PDF), "application/pdf")})
check(f"a signed PDF is kept against draft 0.1 (200, {r.status_code})",
      r.status_code == 200 and r.json()["file"] == "0.1-final.pdf"
      and r.json()["sha256"] == hashlib.sha256(PDF).hexdigest())
r = analyst.post(f"{BASE}/final", data={"version": "0.1"}, files={"file": ("final v2.pdf", io.BytesIO(PDF + b"2"), "application/pdf")})
check("a second final for 0.1 keeps the first", r.status_code == 200 and r.json()["file"] == "0.1-final-2.pdf"
      and analyst.get(f"{BASE}/files/0.1-final.pdf").content == PDF)
for name, form, f, why in (("an .exe", {"version": "0.1"}, ("x.exe", b"MZ..."), ".docx or a .pdf"),
                           ("a .pdf that is not one", {"version": "0.1"}, ("x.pdf", b"PK\x03\x04"), ".docx or a .pdf"),
                           ("no such draft", {"version": "9.9"}, ("x.pdf", PDF), "no draft 9.9")):
    r = analyst.post(f"{BASE}/final", data=form, files={"file": (f[0], io.BytesIO(f[1]), "application/octet-stream")})
    check(f"{name}: refused (400, {r.status_code})", r.status_code == 400 and why in r.json()["detail"])
r = manager.post(f"/api/companies/{CO}/projects/{PJ}/close")
check(f"the project closes (every suggestion decided) ({r.status_code})", r.status_code == 200)
r = analyst.post(f"{BASE}/final", data={"version": "0.2"}, files={"file": ("f.docx", io.BytesIO(b"PK\x03\x04rest"), "application/octet-stream")})
check("a final is still taken on a Closed project", r.status_code == 200 and r.json()["file"] == "0.2-final.docx")
lst = analyst.get(BASE).json()
check("the listing shows 2 drafts and 3 finals with their digests",
      len(lst["drafts"]) == 2 and len(lst["finals"]) == 3 and all(len(x["sha256"]) == 64 for x in lst["finals"]))
check("the project log is hash-chained and intact", hashchain.verify(storage.project_log_path(CO, PJ))["intact"])
for bad in ("../x", "0.1-draft.docx.tmp", "x.docx", "0.9-draft.docx"):
    check(f"file '{bad}' is 404", analyst.get(f"{BASE}/files/{bad}").status_code == 404)
check("another customer's project is 404 here",
      analyst.get(f"/api/companies/{CO}/projects/{zpj['project_id']}/report").status_code == 404)

print("R-D10: the summary check (report_summary.ground)")
groups = [{"rid": "R2000", "srcip": "198.51.100.66", "username": "adm.hd", "ts_first": "2026-09-17 02:04:13+07:00",
           "ts_last": "2026-09-17 02:30:40+07:00", "cnt": 420, "descr": "brute force"},
          {"rid": "R2008", "srcip": "10.20.0.40", "username": "adm.hd", "ts_first": "2026-09-17 02:57:49+07:00",
           "ts_last": "2026-09-17 02:57:54+07:00", "cnt": 4, "descr": "login after brute force"}]
_, known = report_summary.facts("q", groups, [{"from": "rds01.mekong.local", "to": "sql01.mekong.local",
                                               "accounts": ["adm.hd"], "count": 4, "rules": ["R2008"]}])
G = report_summary.ground
check("a paragraph naming only what F1 holds passes",
      G({"text": "จาก 198.51.100.66 เวลา 02:04 บัญชี adm.hd", "refs": ["F1"]}, known) == [])
check("an address no cited finding holds is refused",
      any("203.0.113.9" in p for p in G({"text": "จาก 203.0.113.9", "refs": ["F1"]}, known)))
check("a mistyped account is refused", any("adm.hu" in p for p in G({"text": "บัญชี adm.hu", "refs": ["F1"]}, known)))
check("a time outside the cited finding is refused",
      any("02:45" in p for p in G({"text": "เวลา 02:45", "refs": ["F1"]}, known)))
check("the span's ends are accepted whatever is cited, a minute either side",
      G({"text": "ตั้งแต่ 02:04 ถึง 02:58", "refs": ["F1"]}, known) == [])
check("an address is not read as a time", G({"text": "จาก 10.20.0.40", "refs": ["F2"]}, known) == [])
check("a machine on a confirmed path may be named", G({"text": "ไปยัง sql01", "refs": ["F2"]}, known) == [])
check("a paragraph citing nothing is refused", G({"text": "x", "refs": []}, known) == ["cites no finding"])
reasons = (G({"text": "จาก 203.0.113.9 บัญชี adm.hu เวลา 02:45 ไปยัง web99", "refs": ["F1"]}, known)
           + ["cites no finding"])
th = [report_summary.thai(p) for p in reasons]
check(f"every reason the check gives has its Thai wording ({len(reasons)})",
      len(reasons) == 5 and not any(p == t for p, t in zip(reasons, th))
      and "203.0.113.9" in th[0] and all("อ้างถึง" in t or "ไม่ได้อ้างอิง" in t for t in th))
check("a reason it does not know is kept as written", report_summary.thai("something new") == "something new")

print("R-D10: many findings are summed up per rule so the facts fit the model's window (2026-11-03)")
many = [{"rid": "WIN-BRUTE-1", "srcip": f"203.0.113.{i % 200}", "username": f"user{i}",
         "ts_first": f"2026-04-{1 + i % 28:02d} 0{i % 10}:00:00+07:00",
         "ts_last": f"2026-04-{1 + i % 28:02d} 0{i % 10}:30:00+07:00", "cnt": 10 + i, "descr": "d" * 300}
        for i in range(400)]
many.sort(key=lambda g: g["ts_first"])
many.append({"rid": "WIN-LAT-1", "srcip": "10.50.1.30", "username": "adm.x", "ts_first": "2026-05-01 03:00:00+07:00",
             "ts_last": "2026-05-01 03:05:00+07:00", "cnt": 3, "descr": "rdp"})
text, mk = report_summary.facts(None, many, [])
check(f"400 findings of one rule fit the budget ({len(text)} <= {report_summary.FACT_BUDGET} characters)",
      len(text) <= report_summary.FACT_BUDGET)
check("the rule is one line G1, the lone finding keeps its own number F401",
      list(mk["refs"]) == ["S", "G1", "F401"])
check("G1's label names the rule and how many", mk["labels"] == {"G1": "WIN-BRUTE-1 ทั้ง 400 รายการ"})
check("a paragraph citing G1 may name any of its sources and accounts",
      G({"text": "จาก 203.0.113.199 บัญชี user7", "refs": ["G1"]}, mk) == [])
check("an address none of G1's findings holds is still refused",
      any("198.51.100.9" in p for p in G({"text": "จาก 198.51.100.9", "refs": ["G1"]}, mk)))
check("G1 is not read as a machine", G({"text": "ตามข้อ G1", "refs": ["G1"]}, mk) == [])
check("few findings stay one line each", list(known["refs"]) == ["S", "F1", "F2"] and known["labels"] == {})
sch = report_summary.schema(["F1"])["properties"]
check(f"a paragraph and a recommendation each cite at most {report_summary.MAX_REFS}",
      sch["paragraphs"]["items"]["properties"]["refs"]["maxItems"] == report_summary.MAX_REFS
      == sch["recommendations"]["items"]["properties"]["refs"]["maxItems"])
check("the model must answer recommendations too, from the same references",
      report_summary.schema(["F1"])["required"] == ["paragraphs", "recommendations"]
      and sch["recommendations"]["items"]["properties"]["refs"]["items"]["enum"] == ["F1"])
wide = [{**g, "rid": f"SIGMA-{i}"} for i, g in enumerate(many)]   # 401 rules, one finding each
_ask = report_summary._ask
report_summary._ask = lambda *a: (_ for _ in ()).throw(AssertionError("the model was asked"))
out = real_draft(None, wide, [])
report_summary.llm._preflight = lambda: None


async def _answer(prompt, sch):
    return ({"paragraphs": [{"text": "จาก 198.51.100.66 บัญชี adm.hd", "refs": ["F1"]}],
             "recommendations": [{"text": "ปิดการเข้าถึงจาก 198.51.100.66", "refs": ["F1"]},
                                 {"text": "ตรวจเครื่อง web99", "refs": ["F1"]}]}, {"finish": "stop"})
report_summary._ask = _answer
two = real_draft("q", groups, [])
check("a recommendation is checked as a paragraph is: one kept, one refused for its machine",
      [r["text"] for r in two["recommendations"]] == ["ปิดการเข้าถึงจาก 198.51.100.66"]
      and any("web99" in p for w in two["recommendation_warnings"] for p in w["problems"]))
report_summary._ask = _ask
check("facts that cannot fit are not sent: the draft says why instead",
      out["error"] and "do not fit" in out["error"] and not out["paragraphs"])

print("Tactics: a SigmaHQ finding takes its rule's own tactics (2026-11-03)")
from app.services import rule_meta, rules_sigma, sigma  # noqa: E402
by_rid = sigma.by_rid()
multi = next((rid for rid in rules_sigma.ENTITY
              if len({t.lower().split(".")[0] for t in by_rid[rid]["techniques"]}) > 1
              and by_rid[rid].get("tactics")), None)
if multi is None:
    check("the SigmaHQ bundle is here (no suggesting rule loaded - check skipped)", False)
else:
    own = {rule_meta._TAG_ALIAS.get(x, x) for x in (y.replace("-", "_") for y in by_rid[multi]["tactics"])}
    check(f"{multi[:20]}...: its finding reaches its own tactics only",
          set(rule_meta.finding_tactics(multi, by_rid[multi]["techniques"])) == own)
    t1059 = [rid for rid in rules_sigma.ENTITY if by_rid[rid]["techniques"] == ["T1059"]]
    check("T1059 alone is Execution, as ATT&CK files it (it reached 11 tactics)",
          not t1059 or rule_meta.tactics_of(["T1059"]) == ["execution"])
check("an in-house finding keeps its techniques' tactics",
      rule_meta.finding_tactics("WIN-AUTH-1", ["T1078"]) == rule_meta.tactics_of(["T1078"]))

print(f"\n{'FAILED: ' + str(failures) if failures else 'all ok'}")
sys.exit(1 if failures else 0)
