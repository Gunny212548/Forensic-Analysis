"""Build docs/measurement-method-th.pdf - how the tool measures levels (Thai).

The rule tables, level weights, escalation patterns, Admiralty grades and
lifecycle mapping are read from the code itself (rules.py, rule_meta.py,
severity.py, confidence.py, lifecycle.py), so re-running this after a change
keeps the document true. Measured figures are quoted with their date.

    python tools/build_measurement_doc.py            # writes .html and .pdf
    python tools/build_measurement_doc.py --html-only

Needs Chrome or Edge for the PDF, and the IBM Plex Sans Thai font files from
frontend/node_modules (npm ci in frontend/).
"""

import argparse
import html
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.services import confidence, lifecycle, rule_meta, severity  # noqa: E402
from app.services.rules import RULE_LABELS, RULE_LEVEL, RULES  # noqa: E402

OUT_HTML = ROOT / "docs" / "measurement-method-th.html"
OUT_PDF = ROOT / "docs" / "measurement-method-th.pdf"
FONTS = ROOT / "frontend" / "node_modules" / "@fontsource"

LEVEL_TH = {
    "informational": "ข้อมูลประกอบ (informational)",
    "low": "ต่ำ (low)",
    "medium": "ปานกลาง (medium)",
    "high": "สูง (high)",
    "critical": "วิกฤต (critical)",
}
SIGMA_DEF = {
    "informational": "ใช้ติดป้าย/เสริมข้อมูลเหตุการณ์ ไม่ควรเปิดเคสหรือแจ้งเตือน",
    "low": "เหตุการณ์ที่น่าสังเกตแต่ไม่ค่อยเป็น incident มีความหมายเมื่อเกิดจำนวนมากหรือร่วมกับเหตุการณ์อื่น",
    "medium": "เหตุการณ์ที่เกี่ยวข้อง ควรตรวจสอบด้วยคนเป็นประจำ",
    "high": "ควรแจ้งเตือนภายในและต้องตรวจสอบโดยเร็ว",
    "critical": "บ่งชี้ว่าเป็น incident ต้องตรวจสอบทันที ใช้เมื่อความน่าจะเป็นเกือบแน่นอน",
}
STATUS_TH = {"test": "test", "experimental": "experimental", "stable": "stable"}


def e(s) -> str:
    return html.escape(str(s))


def font_face(family: str, file: str, weight: int) -> str:
    path = FONTS / file
    return (f"@font-face{{font-family:'{family}';font-weight:{weight};"
            f"src:url('{path.as_uri()}') format('woff2');}}")


def rule_rows() -> str:
    out = []
    for rid, _ in RULES:
        m = rule_meta.RULE_META[rid]
        lvl = RULE_LEVEL[rid]
        tech = ", ".join(m["techniques"]) or "-"
        out.append(
            f"<tr><td class='mono'>{e(rid)}</td><td>{e(m['title'])}</td>"
            f"<td class='lv lv-{lvl}'>{e(lvl)}</td><td class='mono'>{e(tech)}</td>"
            f"<td>{e(m['status'])}</td><td>{e(rule_meta._plain(m['falsepositives'][0]))}</td></tr>"
        )
    return "\n".join(out)


def build_html() -> str:
    today = date.today().isoformat()
    W = severity.WEIGHT
    levels = "\n".join(
        f"<tr><td class='lv lv-{k}'>{e(LEVEL_TH[k])}</td><td class='mono c'>{W[k]}</td>"
        f"<td>{e(SIGMA_DEF[k])}</td></tr>" for k in severity.LEVELS)
    pattern_th = {
        "credential-compromise": "ต้นทางเดียวกัน brute-force บัญชีหนึ่ง แล้วตามด้วยการ login สำเร็จเข้าบัญชีนั้น",
        "compromised-host": "host เดียวกันแสดงพฤติกรรมหลังบุกรุกตั้งแต่ 2 แบบที่ต่างกัน และ firewall อนุญาต",
    }
    patterns = "\n".join(
        f"<tr><td class='mono'>{e(p)}</td><td class='lv lv-{lv}'>{e(lv)}</td>"
        f"<td>{e(pattern_th.get(p, reason))}</td></tr>"
        for p, (lv, reason) in severity.PATTERNS.items())
    # One flat table, A-F beside 1-6, so it cannot split from its header.
    admiralty = "\n".join(
        f"<tr><td class='mono c'>{r}</td><td>{e(confidence.RELIABILITY[r])}</td>"
        f"<td class='mono c'>{c}</td><td>{e(confidence.CREDIBILITY[c])}</td></tr>"
        for r, c in zip(confidence.RELIABILITY, confidence.CREDIBILITY))
    csf = "\n".join(f"<tr><td><b>{e(s)}</b></td><td>{e(lifecycle.CSF[s])}</td></tr>"
                    for s in lifecycle.STATES)
    counts = {}
    for rid, _ in RULES:
        counts[RULE_LEVEL[rid]] = counts.get(RULE_LEVEL[rid], 0) + 1
    status_counts = {}
    for rid, _ in RULES:
        s = rule_meta.RULE_META[rid]["status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    css = "\n".join([
        font_face("PlexThai", "ibm-plex-sans-thai/files/ibm-plex-sans-thai-thai-400-normal.woff2", 400),
        font_face("PlexThai", "ibm-plex-sans-thai/files/ibm-plex-sans-thai-latin-400-normal.woff2", 400),
        font_face("PlexThai", "ibm-plex-sans-thai/files/ibm-plex-sans-thai-thai-600-normal.woff2", 600),
        font_face("PlexThai", "ibm-plex-sans-thai/files/ibm-plex-sans-thai-latin-600-normal.woff2", 600),
        font_face("PlexThai", "ibm-plex-sans-thai/files/ibm-plex-sans-thai-thai-700-normal.woff2", 700),
        font_face("PlexThai", "ibm-plex-sans-thai/files/ibm-plex-sans-thai-latin-700-normal.woff2", 700),
        font_face("PlexMono", "ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2", 400),
    ])

    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8">
<title>วิธีวัดระดับผลการวิเคราะห์ - forensic-analyzer</title>
<style>
{css}
@page {{ size: A4; margin: 18mm 16mm 18mm 16mm; }}
body {{ font-family: 'PlexThai', sans-serif; font-size: 10.5pt; line-height: 1.6; color: #1d2330; }}
h1 {{ font-size: 20pt; margin: 0 0 4pt; color: #8a5200; }}
h2 {{ font-size: 14pt; margin: 18pt 0 6pt; border-bottom: 1.5pt solid #b36b00; padding-bottom: 2pt; break-after: avoid; }}
h3 {{ font-size: 11.5pt; margin: 12pt 0 4pt; break-after: avoid; }}
p {{ margin: 4pt 0 6pt; }}
.sub {{ color: #5b6475; font-size: 9.5pt; }}
.mono {{ font-family: 'PlexMono', monospace; font-size: 9pt; }}
.c {{ text-align: center; }}
table {{ border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 9.2pt; break-inside: auto; }}
th, td {{ border: 0.6pt solid #c9ced8; padding: 3pt 5pt; vertical-align: top; text-align: left; }}
th {{ background: #eef0f3; font-weight: 600; }}
tr {{ break-inside: avoid; }}
table.keep {{ break-inside: avoid; }}
th {{ white-space: nowrap; }}
.lv {{ font-weight: 600; white-space: nowrap; }}
.lv-critical {{ color: #b3261e; }} .lv-high {{ color: #b36b00; }} .lv-medium {{ color: #1f5fa8; }}
.lv-low {{ color: #4d5566; }} .lv-informational {{ color: #7a8291; }}
.box {{ border-left: 3pt solid #b36b00; background: #fbf5ec; padding: 6pt 9pt; margin: 8pt 0; }}
.note {{ border-left: 3pt solid #8a93a3; background: #f2f4f7; padding: 6pt 9pt; margin: 8pt 0; }}
code {{ font-family: 'PlexMono', monospace; font-size: 9pt; background: #f2f4f7; padding: 0 2pt; }}
ul {{ margin: 3pt 0 6pt 16pt; padding: 0; }} li {{ margin: 1.5pt 0; }}
.cover {{ margin-bottom: 10pt; }}
</style></head><body>

<div class="cover">
<h1>วิธีวัดระดับผลการวิเคราะห์</h1>
<div class="sub">forensic-analyzer · Finding Response Console · ฉบับวันที่ {today}<br>
ตารางและเกณฑ์ในเอกสารนี้สร้างจากโค้ดของระบบโดยตรง (<code>tools/build_measurement_doc.py</code>)</div>
</div>

<h2>1. วัตถุประสงค์และหลักการ</h2>
<p>เอกสารนี้อธิบายว่าระบบตัดสิน <b>ระดับความรุนแรง</b> ของ finding, <b>ความน่าเชื่อถือ</b> ของ finding,
finding ใดต้อง <b>เข้า workflow</b>, การวัด <b>MTTC</b> และการ <b>จัดอันดับความเสี่ยง</b> อย่างไร</p>
<div class="box">หลักการ: ทุกระดับที่ระบบแสดงต้องอธิบายได้ว่า <b>อ้างอิงมาตรฐานใด</b> และ <b>ตัดสินจากข้อเท็จจริงใด</b>
ในประโยคเดียว ขั้นใดที่ไม่มีมาตรฐานรองรับโดยตรง จะระบุชัดว่าเป็น "วิธีภายใน" พร้อม framework ที่ใกล้ที่สุด</div>
<p>ลำดับการทำงาน: log ที่อัปโหลด → แปลงเป็นข้อมูลกลาง → detection rule สร้าง finding →
กำหนดระดับพื้นฐานตาม Sigma → ปรับตามผลของ firewall → ยกระดับตาม attack path →
ให้คะแนนความน่าเชื่อถือ (Admiralty) → finding ระดับ high ขึ้นไปเข้า workflow</p>

<h2>2. ความรุนแรง (Severity)</h2>
<h3>2.1 ระดับพื้นฐาน: Sigma rule level</h3>
<p>อ้างอิง <b>Sigma rules specification v2.1.0</b> (field <code>level</code>) ทุก detection rule ประกาศระดับของตัวเอง
โดยพิจารณาว่า <i>พฤติกรรมนั้นเพียงลำพัง</i> ตรงกับนิยามใดของ Sigma
ระบบเลิกใช้สเกล 0-15 แบบเดิมที่ไม่มีมาตรฐานรองรับแล้ว</p>
<table class="keep"><tr><th style="width:32%">ระดับ</th><th style="width:10%">น้ำหนัก</th><th>นิยามตาม Sigma (สรุป)</th></tr>
{levels}</table>
<p>น้ำหนักเพิ่มเป็นสองเท่าต่อระดับ ใช้สำหรับ <b>เรียงลำดับและคำนวณคะแนนความเสี่ยงเท่านั้น</b>
ป้ายที่แสดงให้ผู้ใช้เห็นคือชื่อระดับเสมอ</p>
<div class="note">ไม่มี rule เดี่ยวตัวใดได้ระดับ critical เพราะ Sigma สงวน critical ไว้สำหรับกรณีที่ความน่าจะเป็น "เกือบแน่นอน"
ซึ่งเหตุการณ์เดียวใน log แทบไม่เคยถึง ระดับ critical จึงมาจากการยกระดับตาม attack path (ข้อ 2.3) เท่านั้น
ปัจจุบันมี rule ระดับ high {counts.get('high', 0)} ตัว, medium {counts.get('medium', 0)} ตัว,
low {counts.get('low', 0)} ตัว, informational {counts.get('informational', 0)} ตัว</div>

<h3>2.2 การจำกัดระดับเมื่อ firewall ปฏิเสธ</h3>
<p>แถวที่ firewall บล็อก (deny, drop, reject, reset ฯลฯ) จะมีระดับ <b>ไม่เกิน medium</b> ไม่ว่าจะเป็น rule ใด
อ้างอิง <b>ODNI Cyber Threat Framework</b> ซึ่งแบ่งการโจมตีเป็น Preparation → Engagement → Presence → Effect
และกำหนด "เส้นการบุกรุก" ไว้ระหว่าง Engagement กับ Presence ความพยายามที่ถูกบล็อกยังไม่ข้ามเส้นนี้
ตัวอย่างเช่น beacon ไปยัง C2 ที่ถูกบล็อกทุกครั้งเป็นเพียงความพยายาม ยังไม่ใช่ช่องทางที่ติดต่อได้จริง</p>

<h3>2.3 การยกระดับตาม attack path</h3>
<p>เมื่อหลักฐานใน path เดียวกันแสดงว่าการโจมตีข้ามเส้นการบุกรุกแล้ว finding บน path นั้นจะถูกยกระดับ
แต่ละรูปแบบเป็นประโยคที่ analyst ตรวจสอบกับข้อมูลได้ และหน้าจอแสดง rule ที่เป็นหลักฐานกำกับไว้</p>
<table><tr><th>รูปแบบ</th><th>ยกเป็น</th><th>เงื่อนไข</th></tr>
{patterns}</table>
<ul>
<li><b>credential-compromise:</b> ต้องมี brute-force (R2000 คือ fail ≥ 3 ครั้ง) จาก <i>ต้นทางเดียวกัน</i>
แล้วตามด้วยการ login สำเร็จใน <i>บัญชีเดียวกัน</i> จากต้นทางนั้น จึงได้แค่ high ไม่ถึง critical
เพราะ log แยกไม่ออกว่าผู้โจมตีเดารหัสถูก หรือเจ้าของบัญชีพิมพ์ผิดหลายครั้งแล้วเข้าได้</li>
<li><b>compromised-host:</b> host เดียวกันแสดงพฤติกรรมหลังบุกรุก <i>2 แบบที่ต่างกัน</i> ซึ่ง firewall อนุญาต
ได้แก่ beaconing (R2007), traffic ไปยัง IP อันตรายที่ถูกอนุญาต (R3003), traffic ประเภท malware ที่ถูกอนุญาต (R3002)
และการส่งข้อมูลออกขนาดใหญ่ (R3001) แต่ละพฤติกรรมเพียงอย่างเดียวยังมีคำอธิบายที่ไม่เป็นอันตรายได้
แต่สองพฤติกรรมที่เป็นอิสระต่อกันบน host เดียวกันไม่ใช่</li>
</ul>
<div class="note">บทเรียนจากการวัดจริง: เวอร์ชันแรกให้ credential-compromise เป็น critical และนับแค่การเป็นหนึ่งในแหล่งของ password spray
ผลคือ host ที่พิมพ์รหัสผิด 2 ครั้งแล้วเข้าได้ใน 9 วินาที (เป็นการพิมพ์ผิดชัดเจน) ขึ้นเป็น critical จึงปรับเป็นเกณฑ์ปัจจุบัน</div>

<h3>2.4 ระดับของเคส</h3>
<p>ระดับของเคสคือระดับสูงสุดของ finding ในเคสนั้น ถ้า event เดียวตรงกับหลาย rule จะใช้ระดับที่สูงที่สุด
เคสที่มีแต่ finding ระดับ informational จะแสดงเป็น "None" เพราะ Sigma นิยามระดับนี้ว่าไม่ควรแจ้งเตือน</p>

<h2>3. ความน่าเชื่อถือ (Confidence): Admiralty Code</h2>
<p>อ้างอิง <b>Admiralty Code (ระบบ 6×6 ของ NATO)</b> ซึ่งให้คะแนน 2 แกนแยกกัน และเขียนรวมเป็นรหัส เช่น <code>B2</code>
ถ้อยคำของแต่ละระดับใช้ตามสเกลที่เผยแพร่ ส่วน <i>ข้อเท็จจริงใดได้ระดับใด</i> เป็นเกณฑ์ของระบบที่ระบุไว้ด้านล่าง</p>
<table class="keep"><tr><th colspan="2">ความน่าเชื่อถือของแหล่ง (A-F)</th><th colspan="2">ความน่าเชื่อของข้อมูล (1-6)</th></tr>
{admiralty}</table>
<h3>3.1 ตัวอักษร: ความน่าเชื่อถือของแหล่ง log ตามที่ระบบอ่าน</h3>
<ul>
<li><b>A</b> ไม่ให้เลย เพราะตัวอ่าน log ไม่สามารถอ้างได้ว่า "ไม่มีข้อสงสัยใด ๆ"</li>
<li><b>B</b> อ่านคอลัมน์ตามเอกสารของ log source และไฟล์มี hash ที่บันทึกตอนรับเข้า ซึ่ง verify ผ่านทุกครั้ง</li>
<li><b>C</b> อ่านตามเอกสาร แต่ hash บันทึกย้อนหลังหรือไม่มี hash หรือมีบาง field ที่ต้องเดา</li>
<li><b>D</b> คอลัมน์ถูกเดาจากชื่อ ไม่ได้อ่านตามเอกสาร</li>
<li><b>E</b> ไฟล์ไม่ผ่านการตรวจ hash ครั้งล่าสุด</li>
<li><b>F</b> เคสเก่าที่ไม่มีบันทึกว่าอ่านไฟล์อย่างไร</li>
</ul>
<h3>3.2 ตัวเลข: ความน่าเชื่อของ finding</h3>
<ul>
<li><b>1</b> entity เดียวกันปรากฏใน <i>log source อื่น</i> ของเคสเดียวกัน ซึ่งถือเป็นแหล่งอิสระตามความหมายของ Admiralty</li>
<li><b>2</b> มี rule ≥ 2 กลุ่ม (R1 auth / R2 correlation / R3 network) และมี event สนับสนุน ≥ 5 ครั้ง</li>
<li><b>3</b> มี rule กลุ่มเดียว หรือมี event น้อยกว่า 5 ครั้ง</li>
<li><b>4</b> ไม่มี timestamp ที่ parse ได้ หรือ rule ยังเป็น experimental (ยังไม่เคยพิสูจน์กับข้อมูลจริง)</li>
<li><b>5, 6</b> ระบบไม่ให้อัตโนมัติ: การปฏิเสธ finding เป็นหน้าที่ของ analyst ผ่านการ review</li>
</ul>
<p>ป้าย high / medium / low ตาม section 6 ของสเปกยังใช้อยู่ โดยคำนวณจากตัวเลข: 1-2 = high, 3 = medium, 4-6 = low
เมื่อ export เป็น STIX 2.1 ตัวเลขนี้แปลงเป็นค่า <code>confidence</code> ตามตารางของ STIX
(1 = 90, 2 = 70, 3 = 50, 4 = 30, 5 = 10 และ 6 ไม่ระบุค่า)</p>

<h2>4. เกณฑ์เข้า workflow, lifecycle และ MTTC</h2>
<p>finding ที่เข้า workflow คือ finding ระดับ <b>high และ critical</b> ซึ่ง Sigma นิยามว่า "ควรแจ้งเตือนและตรวจสอบโดยเร็ว"
finding ระดับต่ำกว่ายังแสดงในเคส แต่ไม่มีสถานะ workflow</p>
<table><tr><th>สถานะ</th><th>NIST SP 800-61r3 / CSF 2.0</th></tr>{csf}</table>
<ul>
<li>ก่อนเริ่ม investigate ต้องมีผู้รับผิดชอบ</li>
<li>สถานะ Contained ต้องบันทึกว่าดำเนินการ containment อะไรไปบ้าง</li>
<li>การปิด finding ต้อง review แล้ว และระบุ classification (true positive / benign true positive / false positive) พร้อมสรุป</li>
<li><b>true positive ต้องผ่าน Contained ก่อนปิด</b> ส่วน benign TP และ FP ปิดจาก Investigating ได้ทันที</li>
<li><b>MTTC</b> วัดจากเวลาที่ finding ถูกสร้าง (ครั้งแรกที่ rule engine ประมวลผลเคสเสร็จ) ถึงเวลาที่ถึง Contained
และนับเฉพาะ true positive เพื่อไม่ให้ containment ที่ไม่ได้เกิดขึ้นจริงบิดเบือนตัวเลข</li>
</ul>

<h2>5. การจัดอันดับความเสี่ยงของ entity (วิธีภายใน)</h2>
<p>ใช้ตอบคำถาม "ควรดูที่ไหนก่อน" ในเคสที่มี finding หลายพันรายการ</p>
<div class="box">คะแนน = Σ<sub>rule ที่เกี่ยวข้อง</sub> น้ำหนัก × (1 + ln n)
โดยน้ำหนักมาจากระดับ Sigma และ n คือจำนวนแถวของ rule นั้นที่เกี่ยวกับ entity</div>
<p>แต่ละ rule นับเพียงพจน์เดียว และจำนวนครั้งถูกลดทอนด้วย log จึงวัดว่า "entity นี้เกี่ยวข้องกับการโจมตีกี่รูปแบบ"
ไม่ใช่ "มี traffic มากแค่ไหน" ถ้าใช้ผลรวมธรรมดา host ที่ถูก scan และมี rule ที่มี noise มาก 3 ตัว
จะได้อันดับสูงกว่าปลายทาง C2 ที่เป็นภัยจริง</p>
<p><b>ไม่มีมาตรฐานรองรับตรง:</b> framework ที่ใกล้ที่สุดคือ NIST SP 800-30 (ความเสี่ยง = likelihood × impact)
คะแนนนี้เป็นเพียงการเรียงลำดับฝั่ง likelihood เพราะการวัด impact ต้องรู้ความสำคัญของ asset ซึ่งระบบไม่มีข้อมูลนี้
คะแนนเป็นลำดับเท่านั้น ไม่ใช่ความน่าจะเป็น และนำไปเทียบข้ามเคสไม่ได้</p>

<h2>6. ผลการวัดกับข้อมูลจริง (2026-10-12)</h2>
<table><tr><th>รายการ</th><th>ผล</th></tr>
<tr><td>ความถูกต้องของการตรวจจับ (parity)</td><td>corpus 63 ไฟล์: จำนวนแถว, flagged และจำนวนต่อ rule ตรงกับ baseline ทุกไฟล์</td></tr>
<tr><td>ระดับของเคส: High → Medium</td><td>20 เคส ส่วนใหญ่เป็นไฟล์ Palo Alto ที่มีแค่ R3000 ซึ่งเป็น noise</td></tr>
<tr><td>ระดับของเคส: High → Critical</td><td>host ที่ beacon และส่งข้อมูลออก (compromised-host)</td></tr>
<tr><td>ระดับของเคสที่ไม่เปลี่ยน</td><td>ESXi brute-force, Azure spray และ ground truth ฝั่ง auth ยังเป็น High</td></tr>
<tr><td>ป้าย confidence ที่เปลี่ยน</td><td>4 finding ของ rule ที่เป็น experimental ในไฟล์สังเคราะห์ (medium → low) ส่วนที่เหลือเหมือนเดิม</td></tr>
<tr><td>finding ที่เข้า workflow</td><td>Palo Alto 1,516 → 3 · monsoon 1,561 → 12 · Entra ID 34 → 6 · corpus 366 → 39</td></tr>
<tr><td>การจัดอันดับความเสี่ยง</td><td>ปลายทาง beaconing ทั้ง 3 ยังอยู่อันดับต้นหลังเปลี่ยนเป็นน้ำหนักแบบ Sigma</td></tr>
</table>

<h2>7. ข้อจำกัด: สิ่งที่ระบบไม่ได้อ้าง</h2>
<ul>
<li><b>CISA NCISS:</b> ระบบสอดคล้องกับ attribute "Observed Activity" แต่ไม่ได้คำนวณคะแนน NCISS
เพราะต้องใช้ข้อมูลผลกระทบและการกู้คืน ซึ่ง log อย่างเดียวให้ไม่ได้</li>
<li><b>ODNI ↔ ATT&amp;CK:</b> ยังไม่พบเอกสารทางการที่จับคู่ทั้งสองไว้ การจับคู่เป็นของระบบเอง โดยยึดเส้นการบุกรุกที่ ODNI นิยามไว้</li>
<li><b>ไม่มี rule ใดเป็น <i>stable</i></b> ตามนิยามของ Sigma: ตอนนี้มี {status_counts.get('test', 0)} ตัวเป็น test
และ {status_counts.get('experimental', 0)} ตัวเป็น experimental เพราะเพิ่งพิสูจน์กับข้อมูลของลูกค้ารายเดียว</li>
<li>ยังไม่มีรูปแบบ <b>lateral movement</b> เพราะใน corpus ไม่มีข้อมูลที่ใช้ปรับเกณฑ์ได้</li>
<li>เกณฑ์เข้า workflow (high ขึ้นไป) <b>ต่างจากถ้อยคำใน FR-4.3</b> ("Critical หรือ ≥ 2 family")
ซึ่งเขียนไว้สำหรับสเกล 0-15 แบบเดิม</li>
</ul>

<h2>8. ภาคผนวก: ระดับของแต่ละ detection rule</h2>
<p class="sub">level = ระดับพื้นฐานตาม Sigma (ก่อนจำกัดเมื่อถูกบล็อกและก่อนยกระดับ) · status = สถานะตาม Sigma ที่ได้จากหลักฐานการทดสอบ</p>
<table><tr><th>Rule</th><th>ชื่อ</th><th>level</th><th>ATT&amp;CK</th><th>status</th><th>false positive หลัก</th></tr>
{rule_rows()}
</table>

<h2>9. แหล่งอ้างอิง</h2>
<ul>
<li>Sigma rules specification v2.1.0 (field level, status, tags) - SigmaHQ/sigma-specification</li>
<li>Palantir Alerting and Detection Strategy (ADS) framework</li>
<li>ODNI Common Cyber Threat Framework (stages, intrusion boundary)</li>
<li>CISA National Cyber Incident Scoring System / Federal Incident Notification Guidelines</li>
<li>MITRE ATT&amp;CK Enterprise; CISA Best Practices for MITRE ATT&amp;CK Mapping</li>
<li>Admiralty Code / NATO 6×6 (UK JWP 2-00, US FM 2-22)</li>
<li>NIST SP 800-61 Rev. 3 และ NIST CSF 2.0 (RS.MA-02, RS.AN-03, RS.MI-01, RS.MI-02)</li>
<li>NIST SP 800-30 Rev. 1 (risk = likelihood × impact)</li>
<li>OASIS STIX 2.1 (confidence scale mapping)</li>
</ul>
<p class="sub">รายละเอียดการ implement และบันทึกการวัด: CLAUDE.md gotcha #26 (severity), #29 (rule metadata),
#30 (confidence), #33 (lifecycle) และ docs/STANDARDS.md</p>
</body></html>"""


def browser() -> str | None:
    for p in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
              r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chrome")):
        if p and Path(p).exists():
            return p
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--html-only", action="store_true")
    args = ap.parse_args()
    OUT_HTML.parent.mkdir(parents=True, exist_ok=True)
    OUT_HTML.write_text(build_html(), encoding="utf-8")
    print(f"wrote {OUT_HTML}")
    if args.html_only:
        return 0
    exe = browser()
    if not exe:
        print("no Chrome/Edge found - open the HTML and print it to PDF")
        return 1
    subprocess.run([exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={OUT_PDF}", OUT_HTML.as_uri()],
                   check=True, capture_output=True, timeout=120)
    print(f"wrote {OUT_PDF} ({OUT_PDF.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
