"""The report draft's own words in Thai (the user, 2026-11-03: "ยังมีการ ผสม ภาษาอยู่").

The draft is a Thai document for readers with no IT background (docs/specs/forensic_report.md R-D8).
What the system writes into it - tactic names, rule titles, step and area names, product and
format names, reasons - came out in English. Here each gets its Thai, with the standard's own
English term in brackets where there is one (the user's choice: "Thai + English in brackets"),
so a lay reader reads Thai and an expert still finds ATT&CK's or the rule's name.

Proper names stay as written: machines, files, accounts, addresses, technique ids, product
brands, standard documents and the section titles they are cited by. SigmaHQ's rule titles stay
as their authors wrote them (1,492 rules; a title is the rule's name), marked "กฎ SigmaHQ".
Anything this module does not know is returned unchanged - never a guess.
"""
from __future__ import annotations

import re

# MITRE ATT&CK Enterprise tactics (v20), keyed by rule_meta.TACTIC_ORDER's id.
TACTIC = {
    "reconnaissance": "การสอดแนมเป้าหมาย",
    "resource_development": "การเตรียมเครื่องมือและทรัพยากร",
    "initial_access": "การเข้าถึงระบบครั้งแรก",
    "execution": "การสั่งรันโปรแกรมหรือคำสั่ง",
    "persistence": "การฝังตัวให้คงอยู่ในระบบ",
    "privilege_escalation": "การยกระดับสิทธิ์",
    "defense_evasion": "การหลบเลี่ยงการตรวจจับ",
    "defense_impairment": "การทำให้ระบบป้องกันใช้การไม่ได้",
    "credential_access": "การขโมยหรือเดารหัสผ่าน",
    "discovery": "การสำรวจระบบภายใน",
    "lateral_movement": "การเคลื่อนย้ายไปยังเครื่องอื่น",
    "collection": "การรวบรวมข้อมูล",
    "command_and_control": "การสั่งการและควบคุมจากภายนอก",
    "exfiltration": "การนำข้อมูลออกนอกองค์กร",
    "impact": "การสร้างความเสียหายต่อระบบ",
}

# In-house rules (rule_meta.RULE_META, origin not SigmaHQ).
RULE = {
    "R2000": "การเดารหัสผ่านถี่ ๆ จากแหล่งเดียว",
    "R2002": "การสแกนพอร์ต (ถูกปฏิเสธ)",
    "R2003": "การไล่สำรวจบริการ (ถูกปฏิเสธ)",
    "R2004": "ทราฟฟิกที่ผ่านได้จากแหล่งที่ส่วนใหญ่ถูกบล็อก",
    "R2005": "การเดารหัสผ่านบัญชีเดียวจากหลายแหล่ง",
    "R2006": "การเข้าสู่ระบบสำเร็จจากหลายแหล่งภายในหนึ่งชั่วโมง",
    "R2007": "การติดต่อออกไปยังที่อยู่ภายนอกเป็นจังหวะสม่ำเสมอ",
    "R2008": "การเข้าสู่ระบบสำเร็จหลังการเดารหัสผ่าน",
    "R2009": "การลองรหัสผ่านกับหลายบัญชีจากแหล่งเดียว",
    "R3001": "การส่งข้อมูลออกปริมาณมาก",
    "R3002": "ทราฟฟิกในหมวดมัลแวร์หรือการสั่งการจากภายนอก",
    "R3003": "ทราฟฟิกที่ผ่านไปยังที่อยู่อันตรายที่รู้จัก",
    "R3004": "ทราฟฟิกที่ผ่านเข้ามาจากที่อยู่อันตรายที่รู้จัก",
    "R3005": "ความพยายามติดต่อที่อยู่อันตรายที่รู้จัก (ถูกบล็อก)",
    "PAN-SCAN-1": "Palo Alto: การสแกนหลายพอร์ตของเครื่องเดียว",
    "PAN-SCAN-2": "Palo Alto: การสแกนหลายเครื่อง",
    "PAN-SCAN-3": "Palo Alto: ผ่านได้หลังถูกปฏิเสธหลายครั้ง",
    "PAN-MAL-1": "Palo Alto: การติดต่อออกไปยังที่อยู่ภายนอกเป็นจังหวะสม่ำเสมอ",
    "PAN-MAL-2": "Palo Alto: หมวดหมู่อันตรายตาม PAN-DB",
    "PAN-INTEL-1": "Palo Alto: ปลายทางอันตรายที่รู้จัก (ผ่านได้)",
    "PAN-INTEL-2": "Palo Alto: ต้นทางอันตรายที่รู้จัก (ผ่านได้)",
    "PAN-INTEL-3": "Palo Alto: ปลายทางอันตรายที่รู้จัก (ถูกบล็อก)",
    "CP-SCAN-1": "Check Point: การสแกนหลายพอร์ตของเครื่องเดียว",
    "CP-SCAN-2": "Check Point: การสแกนหลายเครื่อง",
    "CP-SCAN-3": "Check Point: ผ่านได้หลังถูกปฏิเสธหลายครั้ง",
    "CP-MAL-1": "Check Point: การติดต่อออกไปยังที่อยู่ภายนอกเป็นจังหวะสม่ำเสมอ",
    "CP-MAL-2": "Check Point: ผลการตรวจของ Threat Prevention",
    "CP-INTEL-1": "Check Point: ปลายทางอันตรายที่รู้จัก (ผ่านได้)",
    "CP-INTEL-2": "Check Point: ต้นทางอันตรายที่รู้จัก (ผ่านได้)",
    "CP-INTEL-3": "Check Point: ปลายทางอันตรายที่รู้จัก (ถูกบล็อก)",
    "WIN-BRUTE-1": "Windows: การเดารหัสผ่าน",
    "WIN-BRUTE-2": "Windows: การลองรหัสผ่านกับหลายบัญชี",
    "WIN-BRUTE-3": "Windows: บัญชีเดียวเข้าสู่ระบบล้มเหลวจากหลายแหล่ง",
    "WIN-BRUTE-4": "Windows: การเดารหัสผ่านอย่างช้า ๆ ขณะที่ความล้มเหลวทั้งองค์กรสูงขึ้น",
    "WIN-AUTH-1": "Windows: เข้าสู่ระบบสำเร็จหลังความล้มเหลวที่ถูกตรวจพบ",
    "WIN-LAT-1": "Windows: การเชื่อมต่อ RDP ที่ไม่ปกติ แล้วมีการรันคำสั่ง",
    "WIN-LAT-2": "Windows: สร้างบริการหรืองานตั้งเวลาผ่านการเข้าสู่ระบบทางเครือข่าย",
    "WIN-LAT-3": "Windows: เข้าสู่ระบบทางเครือข่ายด้วย NTLM โดยไม่มี Kerberos",
    "WIN-LAT-4": "Windows: คัดลอกไฟล์ไปยังแชร์ผู้ดูแลระบบแล้วสั่งรัน",
    "WIN-HOST-1": "Windows: การขอตั๋ว Kerberos เพื่อเจาะรหัสผ่านบัญชีบริการ",
    "WIN-HOST-2": "Windows: อ่านหน่วยความจำ LSASS แล้วเขียนไฟล์",
    "WIN-HOST-3": "Windows: Microsoft Defender ถูกปิดหรือถูกแก้ไขค่า",
    "WIN-MAL-1": "Windows: โปรแกรมติดต่อออกไปภายนอกเป็นจังหวะสม่ำเสมอ",
    "WIN-MAL-2": "Windows: Microsoft Defender ตรวจพบภัยคุกคาม",
    "WIN-INTEL-1": "Windows: การเชื่อมต่อไปยังที่อยู่อันตรายที่รู้จัก",
    "WIN-INTEL-2": "Windows: การเข้าสู่ระบบจากที่อยู่อันตรายที่รู้จัก",
}

# The case page's steps (case_flow.STEPS), as section 3 names what each standard was used for.
STEP = {
    "Ingest": "การรับและอ่านหลักฐาน",
    "Timeline": "การเรียงเหตุการณ์ตามเวลา",
    "Attack events": "การคัดแยกเหตุการณ์การโจมตี",
    "Attack timeline": "ลำดับเวลาการโจมตี",
    "Attack path": "เส้นทางการโจมตี",
    "Report": "การจัดทำรายงาน",
}

# Detection areas (areas.py).
AREA = {
    "Authentication": "การยืนยันตัวตน",
    "Brute force & spraying": "การเดาและลองรหัสผ่าน",
    "Scanning & policy": "การสแกนและนโยบายไฟร์วอลล์",
    "Malware & C2": "มัลแวร์และการสั่งการจากภายนอก",
    "Data transfer": "การส่งข้อมูลออก",
    "Lateral movement": "การเคลื่อนย้ายไปยังเครื่องอื่น",
    "Host activity": "กิจกรรมบนเครื่อง",
    "Threat intelligence": "ข่าวกรองภัยคุกคาม",
}

# Why an area has no rule for a product (products.NOT_APPLICABLE).
NOT_APPLICABLE = {
    "A Palo Alto Traffic log records sessions, not sign-ins (Q61); needs a GlobalProtect or Authentication log":
        "ล็อก Traffic ของ Palo Alto บันทึกการเชื่อมต่อ ไม่ได้บันทึกการเข้าสู่ระบบ "
        "ต้องมีล็อก GlobalProtect หรือ Authentication",
    "Windows Security and Sysmon logs record no refused connection (the Filtering Platform's 5157 would; "
    "not read yet)":
        "ล็อก Security และ Sysmon ของ Windows ไม่บันทึกการเชื่อมต่อที่ถูกปฏิเสธ "
        "(เหตุการณ์ 5157 ของ Windows Filtering Platform บันทึก แต่ระบบยังไม่อ่าน)",
    "Windows Security and Sysmon logs carry no byte counts":
        "ล็อก Security และ Sysmon ของ Windows ไม่มีจำนวนไบต์ที่รับส่ง",
    "A firewall log records connections, not what ran on a host":
        "ล็อกไฟร์วอลล์บันทึกการเชื่อมต่อ ไม่ได้บันทึกว่ามีอะไรทำงานบนเครื่อง",
}

# Why a member of a zip was not analysed (archive.py).
SKIPPED = {
    "encrypted": "ไฟล์ถูกเข้ารหัส",
    "nested zip": "เป็นไฟล์ zip ซ้อนอยู่ข้างใน",
    "compressed file inside zip": "เป็นไฟล์บีบอัดซ้อนอยู่ใน zip",
    "not a log file type": "ไม่ใช่ไฟล์ล็อก",
    "empty": "ไฟล์ว่าง",
}

# How a file was read (the log source profile's name): the kind of log in Thai, the format as named.
FORMAT = {
    "OpenSSH sshd authentication messages": "ข้อความการยืนยันตัวตนของ OpenSSH sshd",
    "Linux-PAM pam_unix password change, session and authentication-failure messages":
        "ข้อความของ Linux-PAM pam_unix (เปลี่ยนรหัสผ่าน, เซสชัน, ยืนยันตัวตนล้มเหลว)",
    "VMware ESXi shell sessions, shell command history, console login, SSH / ESXi Shell on-off":
        "บันทึกของ VMware ESXi (เซสชัน shell, ประวัติคำสั่ง, การเข้าสู่ระบบ, การเปิดปิด SSH / ESXi Shell)",
    "VMware ESXi remote command and PAM per-user lines": "บันทึกคำสั่งระยะไกลและ PAM รายผู้ใช้ของ VMware ESXi",
    "Check Point Log Exporter records (syslog format) in a ManageEngine EventLog Analyzer search export":
        "บันทึก Check Point Log Exporter (รูปแบบ syslog) ในไฟล์ส่งออกจาก ManageEngine EventLog Analyzer",
}
_FORMAT = [
    (re.compile(r"^Windows event log \((.+)\)$"), "บันทึกเหตุการณ์ Windows ({})"),
    (re.compile(r"^(.+) traffic log(.*)$"), "บันทึกทราฟฟิกของ {}{}"),
    (re.compile(r"^(.+) sign-in log(.*)$"), "บันทึกการเข้าสู่ระบบของ {}{}"),
    (re.compile(r"^(.+) message trace$"), "บันทึกการส่งอีเมลของ {}"),
    (re.compile(r"^(.+) log export$"), "ล็อกที่ส่งออกจาก {}"),
]


def tactic(tid: str, english: str) -> str:
    th = TACTIC.get(tid)
    # ATT&CK v20's "Stealth (Defense Evasion)" - no brackets inside the brackets.
    english = re.sub(r"^(.+) \((.+)\)$", r"\1 / \2", english)
    return f"{th} ({english})" if th else english


def rule(rid: str, english: str, origin: str | None = None) -> str:
    """A rule's title for the draft: Thai (English) for ours, SigmaHQ's own title for theirs."""
    if origin == "SigmaHQ" or rid.startswith("SIGMA-"):
        return f"กฎ SigmaHQ: {english}"
    th = RULE.get(rid)
    if not th:
        return english
    # "Windows: การเดารหัสผ่าน (password guessing)" - the product is said once.
    prefix = th.split(": ", 1)[0] + ": " if ": " in th else None
    if prefix and english.startswith(prefix):
        english = english[len(prefix):]
    return f"{th} ({english})"


def step(english: str) -> str:
    th = STEP.get(english)
    return f"{th} ({english})" if th else english


def area(english: str) -> str:
    return AREA.get(english, english)


def not_applicable(reason: str | None) -> str:
    return NOT_APPLICABLE.get(reason or "", reason or "-")


def skipped(reason: str | None) -> str:
    return SKIPPED.get(reason or "", reason or "")


def read_as(name: str | None) -> str:
    if not name:
        return "ไม่ได้อ่าน (เก็บเป็นหลักฐาน)"
    if name in FORMAT:
        return FORMAT[name]
    for pattern, text in _FORMAT:
        m = pattern.match(name)
        if m:
            return text.format(*m.groups())
    return name


def ai_error(error: str | None) -> str:
    """Why the AI wrote nothing, in Thai; the technical cause stays for whoever investigates."""
    e = error or ""
    if "do not fit" in e:
        why = "ข้อค้นพบที่ยืนยันมีมากเกินกว่าที่โมเดล AI จะรับได้ในครั้งเดียว"
    elif "JSONDecodeError" in e or "CutOff" in e or "not whole JSON" in e:
        why = "คำตอบของโมเดล AI ถูกตัดก่อนจบ"
    elif "every paragraph" in e:
        why = "ทุกย่อหน้าที่ AI เขียนอ้างถึงสิ่งที่ไม่มีในข้อค้นพบ ระบบจึงตัดออกทั้งหมด"
    elif "no confirmed finding" in e:
        why = "ยังไม่มีข้อค้นพบที่ยืนยัน"
    elif re.search(r"Connect|Timeout|refused|unreachable|preflight|Ollama", e, re.I):
        why = "ติดต่อโมเดล AI ไม่ได้"
    else:
        why = "เกิดข้อผิดพลาดระหว่างที่ AI ร่าง"
    return f"{why} (รายละเอียดทางเทคนิค: {e})" if e else why
