"""Generate three months of Windows Security and Sysmon logs of a small domain, attacks buried in it.

    python tests/gen_windows_domain.py <outdir> [--seed N]

Format: Windows event XML, one `<Event>` per line - what `wevtutil qe /f:xml` and
`Get-WinEvent .ToXml()` write, read by app/services/winevent.py (W1). One file per
host and channel, as an analyst collecting each machine's logs would have them, and
a zip of all of them, which is one case - so a rule sees the domain controller's
Kerberos events beside the member server's logons.

Writes, for the fictitious "Mekong Parts" (domain MEKONG.LOCAL, ~40 staff, GMT+7,
2026-07-01 .. 2026-09-30):

  <HOST>-Security.xml / <HOST>-Sysmon.xml   per host: DC01, FS01, SQL01, RDS01, WS001-WS040
  mekong-windows-2026Q3.zip                 all of the above (= one case)
  ground_truth.csv                          host, channel, record id, time, event id, label,
                                            incident, stage, technique, the rule expected to
                                            find it - for every event that is not plain work
  README.md                                 the incidents and the look-alikes, in words

Labels in ground_truth.csv:
  attack            part of an incident; a rule should find it
  btp               benign, but the behaviour is real (a stale service-account password
                    hammering a share, an agent deployed to every server) - a finding the
                    analyst closes as a benign true positive is the right outcome
  lookalike         ordinary work shaped like an attack (admins on RDP running PowerShell,
                    RC4 tickets for a legacy application, the antivirus opening lsass, a
                    scanner authenticating over NTLM, OneDrive syncing on a timer) - a
                    finding on it is a false positive

Incidents (each event the specs/windows_rules.md rule names should find):
  W1 Jul 14  Kerberos password spray from a guest-network device against every account,
             one password; one account falls (4771 0x18 / 0x6 on DC01, then a 4768)
  W2 Jul 22  RDP brute force from the internet against RDS01's administrator, 800 tries,
             no success (4625 on RDS01)
  W3 Jul-Sep low-and-slow guessing on RDS01 from rotating internet addresses, 3 a day
             (a known gap: B5 is not in story 5a - expected to be missed, and said so)
  W4 Aug 3   phishing on WS023: Outlook -> Word -> PowerShell -> updater.exe, which then
             beacons to 203.0.113.77:443 every ~5 minutes until Sep 20 (Sysmon 1 / 11 / 3)
  W5 Aug 10  Kerberoasting from WS023: RC4 tickets for 14 service accounts in 90 s (4769)
  W6 Aug 17  password guessing against adm.backup over NTLM from WS023 to FS01, 280 tries,
             then success (4625 on FS01 + 4776 on DC01 for the same attempts)
  W7 Sep 1   RDP from WS023 to RDS01 as adm.backup (a first-time pair), discovery commands,
             procdump of lsass (4624 type 10, 4688, Sysmon 1 / 10 / 11)
  W9 Aug 28  distributed guessing against adm.it on RDS01 from 30 internet addresses in 45
             minutes, two or three tries each, no success (4625 on RDS01)
  W8 Sep 2   pass-the-hash as adm.it from WS023 to FS01, SQL01 and DC01 (NTLM network
             logons, no Kerberos for adm.it from WS023), then PsExec-style service on SQL01
             (4697 in that logon session, services.exe -> PSEXESVC.exe -> cmd.exe)

Nothing here comes from a real customer; the names, the domain and every address are
invented (192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are documentation ranges).
"""

import argparse
import csv
import pathlib
import random
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

TZ = timezone(timedelta(hours=7))
START = datetime(2026, 7, 1, tzinfo=TZ)   # Wednesday
DAYS = 92                                 # to 2026-09-30 inclusive
DOMAIN, NETBIOS = "MEKONG.LOCAL", "MEKONG"
DOMAIN_SID = "S-1-5-21-3141592653-2718281828-1618033988"
SEC_PROVIDER = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}")
SYS_PROVIDER = ("Microsoft-Windows-Sysmon", "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}")
SYS_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
# Task category of each Security event (its Microsoft page), and the keywords of success / failure.
TASK = {4624: 12544, 4625: 12544, 4672: 12548, 4688: 13312, 4697: 12289, 4698: 12804,
        4740: 13824, 4768: 14339, 4769: 14337, 4771: 14339, 4776: 14336}
OK_KW, FAIL_KW = "0x8020000000000000", "0x8010000000000000"
SYSMON_TASK = {1: 1, 3: 3, 10: 10, 11: 11}

SERVERS = {"DC01": "10.20.0.10", "FS01": "10.20.0.20", "SQL01": "10.20.0.30", "RDS01": "10.20.0.40"}
PRINTER = ("MFP-2F", "10.20.30.5")
GUEST_DEVICE = "10.20.50.23"              # W1: a device on the guest / IoT network
C2 = "203.0.113.77"
VPN_POOL = "10.20.200"
SAAS = ["52.96.165.18", "142.250.204.46", "13.107.42.14", "20.190.160.20", "104.18.32.7",
        "151.101.1.140", "172.217.24.110", "31.13.75.35"]
ONEDRIVE = "13.107.42.12"
DEFENDER_CLOUD = "20.42.65.92"
INTERNET_BRUTE = "45.155.205.99"          # W2
SLOW_NETS = ["185.220.101", "193.32.162", "91.240.118", "80.66.88"]   # W3

FIRST = ["Somchai", "Suda", "Anan", "Pornthip", "Kittisak", "Nattaya", "Wichai", "Siriporn",
         "Prasert", "Kanya", "Thanakorn", "Malee", "Surasak", "Ratana", "Chaiwat", "Duangjai",
         "Ekachai", "Jintana", "Narong", "Orathai", "Pichit", "Rungnapa", "Sakda", "Thida",
         "Udom", "Wanida", "Yupin", "Boonmee", "Chanida", "Daeng"]
LAST = ["Srisuk", "Wongsa", "Chaiyaporn", "Kaewmanee", "Thongdee", "Rattanakul", "Saetang",
        "Bunnag", "Phromma", "Inthara", "Jaidee", "Sombat"]
# Service accounts and the service each one runs (its SPN); legacy only takes RC4 (W5 look-alike).
SPN_ACCOUNTS = ["svc_sql", "svc_web", "svc_legacy", "svc_report", "svc_crm", "svc_hr", "svc_ftp",
                "svc_monitor", "svc_av", "svc_print", "svc_erp", "svc_dev", "svc_test", "svc_old"]
SPN = {a: f"{a.split('_')[1].upper()}/{('SQL01' if i % 2 else 'FS01')}.{DOMAIN.lower()}"
       for i, a in enumerate(SPN_ACCOUNTS)}
SPN["svc_sql"] = f"MSSQLSvc/SQL01.{DOMAIN.lower()}:1433"
SPN["svc_legacy"] = f"LegacyApp/SQL01.{DOMAIN.lower()}"
LEGACY_USERS = 6                          # finance users of the RC4-only legacy application

T = {"spray": "T1110.003", "guess": "T1110.001", "brute": "T1110", "phish": "T1566.001",
     "ps": "T1059.001", "c2": "T1071.001", "roast": "T1558.003", "rdp": "T1021.001",
     "disc": "T1087.002", "lsass": "T1003.001", "pth": "T1550.002", "psexec": "T1569.002",
     "smb": "T1021.002", "valid": "T1078"}


def utc(ts: datetime) -> datetime:
    return ts.astimezone(timezone.utc)


def system_time(ts: datetime) -> str:
    return utc(ts).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


class Host:
    def __init__(self, name: str, ip: str, rng: random.Random):
        self.name, self.ip = name, ip
        self.fqdn = f"{name.lower()}.{DOMAIN.lower()}"
        self.account = f"{name}$"
        self._logon = rng.randrange(0x200000, 0x800000)
        self._pid = rng.randrange(0x400, 0x2000)
        self.guid_prefix = f"{rng.getrandbits(32):08x}"

    def logon_id(self, rng) -> str:
        self._logon += rng.randrange(0x100, 0x4000)
        return hex(self._logon)

    def pid(self, rng) -> int:
        self._pid += rng.randrange(4, 400)
        return self._pid


class Gen:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.events: list[tuple] = []     # (ts, host, channel, event_id, data, failure, tag)
        self.hosts = {n: Host(n, ip, self.rng) for n, ip in SERVERS.items()}
        self.users = self._users()
        for u in self.users:
            self.hosts[u["ws"]] = Host(u["ws"], u["ip"], self.rng)
        self.rid = 1100
        self.sid = {}
        for name in ([u["login"] for u in self.users] + SPN_ACCOUNTS
                     + ["adm.it", "adm.hd", "adm.backup", "svc_backup", "svc_scan", "Administrator"]):
            self.sid[name.lower()] = f"{DOMAIN_SID}-{self.rid}"
            self.rid += self.rng.randrange(1, 9)
        self.sid["administrator"] = f"{DOMAIN_SID}-500"

    # ----------------------------------------------------------- people
    def _users(self):
        rng, out, seen = self.rng, [], set()
        for i in range(40):
            while True:
                first, last = rng.choice(FIRST), rng.choice(LAST)
                login = f"{first.lower()}.{last[0].lower()}"
                if login not in seen:
                    seen.add(login)
                    break
            out.append({"login": login, "ws": f"WS{i + 1:03d}", "ip": f"10.20.10.{11 + i}",
                        "laptop": i % 4 == 0, "finance": i < LEGACY_USERS})
        # The phished user of W4 - W8 sits at WS023.
        out[22]["login"] = "j.duangjai"
        return out

    def user_sid(self, name: str) -> str:
        n = name.lower().split("@")[0]
        if n.startswith("nt authority"):
            return "S-1-5-18"
        if n.endswith("$"):
            return f"{DOMAIN_SID}-{1000 + sum(map(ord, n)) % 900}"
        return self.sid.get(n, "NULL SID")

    # ----------------------------------------------------------- primitives
    def sec(self, ts, host, eid, data, tag=None, failure=False):
        self.events.append((ts, host, "Security", eid, data, failure, tag))

    def sysmon(self, ts, host, eid, data, tag=None):
        self.events.append((ts, host, SYS_CHANNEL, eid, data, False, tag))

    def guid(self, host) -> str:
        h = self.hosts[host]
        return f"{{{h.guid_prefix}-{self.rng.getrandbits(16):04x}-{self.rng.getrandbits(16):04x}-" \
               f"{self.rng.getrandbits(16):04x}-{self.rng.getrandbits(48):012x}}}"

    def logon(self, ts, host, user, ltype, src_ip="-", workstation="-", pkg="Kerberos", tag=None,
              admin=False):
        """4624 on `host`, and 4672 for an administrator. Returns the new logon id."""
        h = self.hosts[host]
        lid = h.logon_id(self.rng)
        network = ltype == 3
        ntlm = pkg == "NTLM"
        if network:
            subj = ("NULL SID", "-", "-", "0x0")
            proc, proc_id, lproc = "-", "0x0", ("NtLmSsp" if ntlm else "Kerberos")
        elif ltype == 5:
            subj = ("S-1-5-18", h.account, NETBIOS, "0x3e7")
            proc, proc_id, lproc, pkg = r"C:\Windows\System32\services.exe", "0x2a8", "Advapi", "Negotiate"
        else:
            subj = ("S-1-5-18", h.account, NETBIOS, "0x3e7")
            proc, proc_id, lproc, pkg = r"C:\Windows\System32\svchost.exe", "0x3b4", "User32", "Negotiate"
        data = [("SubjectUserSid", subj[0]), ("SubjectUserName", subj[1]), ("SubjectDomainName", subj[2]),
                ("SubjectLogonId", subj[3]), ("TargetUserSid", self.user_sid(user)),
                ("TargetUserName", user), ("TargetDomainName", NETBIOS), ("TargetLogonId", lid),
                ("LogonType", str(ltype)), ("LogonProcessName", lproc), ("AuthenticationPackageName", pkg),
                ("WorkstationName", workstation if (ntlm or not network) else "-"),
                ("LogonGuid", "{00000000-0000-0000-0000-000000000000}" if ntlm else
                 "{" + str(uuid.UUID(int=self.rng.getrandbits(128))).upper() + "}"),
                ("TransmittedServices", "-"), ("LmPackageName", "NTLM V2" if ntlm else "-"),
                ("KeyLength", "128" if ntlm else "0"), ("ProcessId", proc_id), ("ProcessName", proc),
                ("IpAddress", src_ip), ("IpPort", str(self.rng.randrange(49152, 65535)) if src_ip not in
                                        ("-", "127.0.0.1") else ("0" if src_ip == "127.0.0.1" else "-")),
                ("ImpersonationLevel", "%%1833"), ("RestrictedAdminMode", "-"),
                ("TargetOutboundUserName", "-"), ("TargetOutboundDomainName", "-"),
                ("VirtualAccount", "%%1843"), ("TargetLinkedLogonId", "0x0"),
                ("ElevatedToken", "%%1842" if admin else "%%1843")]
        self.sec(ts, host, 4624, data, tag)
        if admin:
            self.sec(ts, host, 4672, [("SubjectUserSid", self.user_sid(user)), ("SubjectUserName", user),
                                      ("SubjectDomainName", NETBIOS), ("SubjectLogonId", lid),
                                      ("PrivilegeList", "SeSecurityPrivilege SeBackupPrivilege "
                                       "SeRestorePrivilege SeDebugPrivilege SeImpersonatePrivilege")], tag)
        return lid

    def logon_fail(self, ts, host, user, ltype, src_ip, workstation, sub="0xc000006a", pkg="NTLM", tag=None):
        h = self.hosts[host]
        network = ltype == 3
        subj = ("NULL SID", "-", "-", "0x0") if network else ("S-1-5-18", h.account, NETBIOS, "0x3e7")
        data = [("SubjectUserSid", subj[0]), ("SubjectUserName", subj[1]), ("SubjectDomainName", subj[2]),
                ("SubjectLogonId", subj[3]), ("TargetUserSid", "NULL SID"), ("TargetUserName", user),
                ("TargetDomainName", NETBIOS if network else NETBIOS), ("Status", "0xc000006d"),
                ("FailureReason", "%%2313"), ("SubStatus", sub), ("LogonType", str(ltype)),
                ("LogonProcessName", "NtLmSsp " if pkg == "NTLM" else "User32 "),
                ("AuthenticationPackageName", pkg if network else "Negotiate"),
                ("WorkstationName", workstation), ("TransmittedServices", "-"),
                ("LmPackageName", "-"), ("KeyLength", "0"),
                ("ProcessId", "0x0" if network else "0x3b4"),
                ("ProcessName", "-" if network else r"C:\Windows\System32\svchost.exe"),
                ("IpAddress", src_ip), ("IpPort", "0" if src_ip == "127.0.0.1" else
                                        str(self.rng.randrange(49152, 65535)))]
        self.sec(ts, host, 4625, data, tag, failure=True)

    def tgt(self, ts, user, ip, status="0x0", etype="0x12", tag=None):
        self.sec(ts, "DC01", 4768, [
            ("TargetUserName", user), ("TargetDomainName", DOMAIN), ("TargetSid", self.user_sid(user)),
            ("ServiceName", "krbtgt"), ("ServiceSid", f"{DOMAIN_SID}-502"), ("TicketOptions", "0x40810010"),
            ("Status", status), ("TicketEncryptionType", etype if status == "0x0" else "0xffffffff"),
            ("PreAuthType", "2"), ("IpAddress", f"::ffff:{ip}"),
            ("IpPort", str(self.rng.randrange(49152, 65535))),
            ("CertIssuerName", ""), ("CertSerialNumber", ""), ("CertThumbprint", "")],
            tag, failure=status != "0x0")

    def tgs(self, ts, user, service, ip, etype="0x12", tag=None):
        self.sec(ts, "DC01", 4769, [
            ("TargetUserName", f"{user}@{DOMAIN}"), ("TargetDomainName", DOMAIN),
            ("ServiceName", service), ("ServiceSid", self.user_sid(service)),
            ("TicketOptions", "0x40810000"), ("TicketEncryptionType", etype),
            ("IpAddress", f"::ffff:{ip}"), ("IpPort", str(self.rng.randrange(49152, 65535))),
            ("Status", "0x0"), ("LogonGuid", "{" + str(uuid.UUID(int=self.rng.getrandbits(128))).upper() + "}"),
            ("TransmittedServices", "-")], tag)

    def preauth_fail(self, ts, user, ip, code="0x18", tag=None):
        self.sec(ts, "DC01", 4771, [
            ("TargetUserName", user), ("TargetSid", self.user_sid(user) if code != "0x6" else "NULL SID"),
            ("ServiceName", f"krbtgt/{DOMAIN}"), ("TicketOptions", "0x40810010"), ("Status", code),
            ("PreAuthType", "2"), ("IpAddress", f"::ffff:{ip}"),
            ("IpPort", str(self.rng.randrange(49152, 65535))),
            ("CertIssuerName", ""), ("CertSerialNumber", ""), ("CertThumbprint", "")], tag, failure=True)

    def ntlm_check(self, ts, user, workstation, status="0x0", tag=None):
        self.sec(ts, "DC01", 4776, [
            ("PackageName", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"), ("TargetUserName", user),
            ("Workstation", workstation), ("Status", status)], tag, failure=status != "0x0")

    def process(self, ts, host, user, lid, image, cmd, parent=None, tag=None, elevated=False):
        """A process: Sysmon 1 and 4688 on `host`, in logon session `lid`. Returns its record."""
        h = self.hosts[host]
        pid, guid = h.pid(self.rng), self.guid(host)
        par = parent or {"image": r"C:\Windows\explorer.exe", "pid": 0x1a4c, "guid": self.guid(host),
                         "cmd": r"C:\Windows\Explorer.EXE"}
        domain_user = user if user.startswith("NT AUTHORITY") else f"{NETBIOS}\\{user}"
        self.sysmon(ts, host, 1, [
            ("RuleName", "-"), ("UtcTime", utc(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
            ("ProcessGuid", guid), ("ProcessId", str(pid)), ("Image", image),
            ("FileVersion", "-"), ("Description", "-"), ("Product", "-"), ("Company", "-"),
            ("OriginalFileName", image.rsplit("\\", 1)[-1]), ("CommandLine", cmd),
            ("CurrentDirectory", "C:\\Windows\\system32\\"), ("User", domain_user),
            ("LogonGuid", "{" + str(uuid.UUID(int=self.rng.getrandbits(128))) + "}"), ("LogonId", lid),
            ("TerminalSessionId", "1"), ("IntegrityLevel", "High" if elevated else "Medium"),
            ("Hashes", f"SHA256={self.rng.getrandbits(256):064X}"), ("ParentProcessGuid", par["guid"]),
            ("ParentProcessId", str(par["pid"])), ("ParentImage", par["image"]),
            ("ParentCommandLine", par["cmd"]), ("ParentUser", domain_user)], tag)
        self.sec(ts, host, 4688, [
            ("SubjectUserSid", self.user_sid(user)), ("SubjectUserName", user.split("\\")[-1]),
            ("SubjectDomainName", NETBIOS), ("SubjectLogonId", lid), ("NewProcessId", hex(pid)),
            ("NewProcessName", image), ("TokenElevationType", "%%1937" if elevated else "%%1938"),
            ("ProcessId", hex(par["pid"])), ("CommandLine", cmd), ("TargetUserSid", "NULL SID"),
            ("TargetUserName", "-"), ("TargetDomainName", "-"), ("TargetLogonId", "0x0"),
            ("ParentProcessName", par["image"]),
            ("MandatoryLabel", "Mandatory Label\\High Mandatory Level" if elevated
             else "Mandatory Label\\Medium Mandatory Level")], tag)
        return {"image": image, "pid": pid, "guid": guid, "cmd": cmd, "user": domain_user}

    def connect(self, ts, host, proc, dst, port, tag=None):
        h = self.hosts[host]
        self.sysmon(ts, host, 3, [
            ("RuleName", "-"), ("UtcTime", utc(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
            ("ProcessGuid", proc["guid"]), ("ProcessId", str(proc["pid"])), ("Image", proc["image"]),
            ("User", proc["user"]), ("Protocol", "tcp"), ("Initiated", "true"), ("SourceIsIpv6", "false"),
            ("SourceIp", h.ip), ("SourceHostname", h.fqdn), ("SourcePort", str(self.rng.randrange(49152, 65535))),
            ("SourcePortName", "-"), ("DestinationIsIpv6", "false"), ("DestinationIp", dst),
            ("DestinationHostname", "-"), ("DestinationPort", str(port)),
            ("DestinationPortName", {443: "https", 445: "microsoft-ds", 3389: "ms-wbt-server"}.get(port, "-"))],
            tag)

    def lsass_open(self, ts, host, proc, access, tag=None):
        self.sysmon(ts, host, 10, [
            ("RuleName", "-"), ("UtcTime", utc(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
            ("SourceProcessGUID", proc["guid"]), ("SourceProcessId", str(proc["pid"])),
            ("SourceThreadId", str(self.rng.randrange(1000, 9000))), ("SourceImage", proc["image"]),
            ("TargetProcessGUID", self.lsass_guid[host]), ("TargetProcessId", "712"),
            ("TargetImage", r"C:\Windows\system32\lsass.exe"), ("GrantedAccess", access),
            ("CallTrace", r"C:\Windows\SYSTEM32\ntdll.dll+9d204|C:\Windows\System32\KERNELBASE.dll+2c13e"),
            ("SourceUser", proc["user"]), ("TargetUser", "NT AUTHORITY\\SYSTEM")], tag)

    def file_created(self, ts, host, proc, path, tag=None):
        self.sysmon(ts, host, 11, [
            ("RuleName", "-"), ("UtcTime", utc(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
            ("ProcessGuid", proc["guid"]), ("ProcessId", str(proc["pid"])), ("Image", proc["image"]),
            ("TargetFilename", path), ("CreationUtcTime", utc(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
            ("User", proc["user"])], tag)

    def service(self, ts, host, user, lid, name, path, tag=None):
        self.sec(ts, host, 4697, [
            ("SubjectUserSid", self.user_sid(user)), ("SubjectUserName", user), ("SubjectDomainName", NETBIOS),
            ("SubjectLogonId", lid), ("ServiceName", name), ("ServiceFileName", path),
            ("ServiceType", "0x10"), ("ServiceStartType", "3"), ("ServiceAccount", "LocalSystem")], tag)

    def task(self, ts, host, name, tag=None):
        self.sec(ts, host, 4698, [
            ("SubjectUserSid", "S-1-5-18"), ("SubjectUserName", self.hosts[host].account),
            ("SubjectDomainName", NETBIOS), ("SubjectLogonId", "0x3e7"), ("TaskName", name),
            ("TaskContent", "<Task><Actions><Exec><Command>C:\\Windows\\System32\\usoclient.exe</Command>"
                            "</Exec></Actions></Task>")], tag)

    # ----------------------------------------------------------- a day of work
    def at(self, day: datetime, h: float, spread: float = 0.0) -> datetime:
        minutes = (h + self.rng.uniform(-spread, spread)) * 60
        return day + timedelta(minutes=minutes, seconds=self.rng.uniform(0, 59),
                               microseconds=self.rng.randrange(0, 999999))

    def machine_day(self, day):
        """Every computer's own account: a TGT at boot, group-policy logons to DC01 through the day.
        DC01's own account signs in to itself from its address and the loopback (the R2006 look-alike)."""
        for name, h in self.hosts.items():
            if name == "DC01":
                for k in range(6):
                    ts = self.at(day, 1 + k * 4, 0.5)
                    self.logon(ts, "DC01", h.account, 3, self.rng.choice([h.ip, "127.0.0.1", "::1"]))
                continue
            self.tgt(self.at(day, 7.5, 0.4), h.account, h.ip)
            for k in range(3):
                self.logon(self.at(day, 9 + k * 3, 1), "DC01", h.account, 3, h.ip)

    def defender(self, day):
        """MsMpEng reads lsass on every server once a day (0x1010, no file written) - the W7 look-alike."""
        for name in SERVERS:
            ts = self.at(day, 3, 1)
            av = {"image": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe",
                  "pid": 3120, "guid": self.av_guid[name], "cmd": "MsMpEng.exe", "user": "NT AUTHORITY\\SYSTEM"}
            self.lsass_open(ts, name, av, "0x1010", ("lookalike", "-", "antivirus reads lsass", T["lsass"]))

    def user_day(self, day, u, workday: bool):
        rng = self.rng
        if not workday:
            if rng.random() > 0.08:
                return
        remote = u["laptop"] and workday and rng.random() < 0.3
        ws, login = u["ws"], u["login"]
        src = f"{VPN_POOL}.{rng.randrange(10, 250)}" if remote else u["ip"]
        start = self.at(day, 8.4, 0.6)
        # A mistyped password now and then: 4625 on the workstation, 4771 on DC01 for the same attempt.
        if rng.random() < 0.05:
            for _ in range(rng.choice([1, 1, 1, 2, 3])):
                t = start - timedelta(seconds=rng.uniform(8, 40))
                self.logon_fail(t, ws, login, 2, "127.0.0.1", ws, pkg="Negotiate")
                self.preauth_fail(t + timedelta(milliseconds=rng.randrange(5, 300)), login, src)
        self.tgt(start, login, src)
        lid = self.logon(start + timedelta(seconds=1), ws, login, 2, "127.0.0.1", ws)
        self.tgs(start + timedelta(seconds=2), login, f"{ws}$", src)
        self.tgs(start + timedelta(seconds=3), login, "DC01$", src)
        explorer = self.process(start + timedelta(seconds=4), ws, login, lid, r"C:\Windows\explorer.exe",
                                r"C:\Windows\Explorer.EXE")
        apps = [(r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", '"OUTLOOK.EXE"'),
                (r"C:\Program Files\Google\Chrome\Application\chrome.exe", '"chrome.exe"'),
                (r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "/background")]
        procs = {}
        for i, (img, cmd) in enumerate(apps):
            img = img.replace("{u}", login)
            procs[i] = self.process(start + timedelta(seconds=10 + i * 3), ws, login, lid, img, cmd, explorer)
        if u["finance"]:
            # The RC4-only legacy application, every working day (the W5 look-alike).
            self.tgs(self.at(day, 9.2, 0.5), login, "svc_legacy", src, "0x17",
                     ("lookalike", "-", "legacy application asks for an RC4 ticket", T["roast"]))
        # Work on the file server through the day.
        self.tgs(start + timedelta(seconds=30), login, "FS01$", src)
        for _ in range(rng.randint(1, 3)):
            self.logon(self.at(day, rng.uniform(9, 17)), "FS01", login, 3, src)
        if rng.random() < 0.4:
            self.tgs(self.at(day, 10, 1), login, "svc_sql", src)
            self.logon(self.at(day, 10.5, 1), "SQL01", login, 3, src)
        # Browsing, and OneDrive's two-hourly sync (regular, to a public address - a beacon look-alike).
        for _ in range(rng.randint(3, 8)):
            self.connect(self.at(day, rng.uniform(9, 17.5)), ws, procs[1], rng.choice(SAAS), 443)
        for k in range(5):
            self.connect(start + timedelta(hours=1 + 2 * k, seconds=rng.uniform(-50, 50)), ws, procs[2],
                         ONEDRIVE, 443, ("lookalike", "-", "OneDrive sync on a timer", T["c2"]))
        # An occasional unlock.
        if rng.random() < 0.5:
            self.logon(self.at(day, 13.2, 0.5), ws, login, 7, "127.0.0.1", ws)
        if rng.random() < 0.02:
            self.task(self.at(day, 12, 3), ws, r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan")

    def admin_day(self, day):
        """IT's own work: adm.it on RDP to the servers with PowerShell and MMC (the W7 look-alike),
        the helpdesk on workstations, the backup job, the scanner over NTLM (the W8 look-alike)."""
        rng = self.rng
        it_ws = self.hosts["WS003"]
        if day.weekday() < 5 and rng.random() < 0.55:
            for target in rng.sample(["RDS01", "SQL01", "FS01"], rng.randint(1, 2)):
                ts = self.at(day, rng.uniform(9.5, 16))
                self.tgt(ts - timedelta(seconds=3), "adm.it", it_ws.ip)
                self.tgs(ts - timedelta(seconds=2), "adm.it", f"{target}$", it_ws.ip)
                tag = ("lookalike", "-", "administrator on RDP", T["rdp"])
                lid = self.logon(ts, target, "adm.it", 10, it_ws.ip, target, "Negotiate", tag, admin=True)
                shell = self.process(ts + timedelta(seconds=5), target, "adm.it", lid,
                                     r"C:\Windows\System32\rdpclip.exe", "rdpclip", tag=tag)
                for img, cmd in rng.sample([
                        (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         "powershell.exe -NoProfile Get-Service | Where Status -eq Stopped"),
                        (r"C:\Windows\System32\cmd.exe", "cmd.exe /c ipconfig /all"),
                        (r"C:\Windows\System32\mmc.exe", r'"C:\Windows\system32\mmc.exe" eventvwr.msc'),
                        (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         "powershell.exe Get-EventLog System -Newest 50"),
                        (r"C:\Windows\System32\taskmgr.exe", "taskmgr.exe /4")], 3):
                    self.process(ts + timedelta(minutes=rng.uniform(1, 25)), target, "adm.it", lid, img, cmd,
                                 shell, tag, elevated=True)
        if day.weekday() < 5:
            for _ in range(rng.randint(0, 2)):
                u = rng.choice(self.users)
                ts = self.at(day, rng.uniform(9, 17))
                self.tgs(ts - timedelta(seconds=1), "adm.hd", f"{u['ws']}$", self.hosts["WS007"].ip)
                self.logon(ts, u["ws"], "adm.hd", 3, self.hosts["WS007"].ip, admin=True)
            # The scanner on the second floor files scans to FS01 with NTLM and never uses Kerberos.
            for _ in range(rng.randint(3, 12)):
                ts = self.at(day, rng.uniform(8.5, 17.5))
                tag = ("lookalike", "-", "scanner authenticates over NTLM", T["pth"])
                self.ntlm_check(ts, "svc_scan", PRINTER[0], tag=tag)
                self.logon(ts + timedelta(milliseconds=40), "FS01", "svc_scan", 3, PRINTER[1], PRINTER[0],
                           "NTLM", tag)
        # The nightly backup.
        ts = self.at(day, 1, 0.1)
        self.logon(ts - timedelta(minutes=1), "SQL01", "svc_backup", 5)
        if not self.stale_backup(ts):
            self.tgt(ts, "svc_backup", SERVERS["SQL01"])
            self.logon(ts + timedelta(seconds=2), "FS01", "svc_backup", 3, SERVERS["SQL01"])

    # ----------------------------------------------------------- benign true positives
    def stale_backup(self, ts) -> bool:
        """Aug 25-27: svc_backup's password was changed and the job on SQL01 kept the old one -
        a Kerberos failure every 15 minutes for two days, from one server, no success."""
        first = datetime(2026, 8, 25, 0, 50, tzinfo=TZ)
        last = datetime(2026, 8, 27, 10, 30, tzinfo=TZ)
        if not first.date() <= ts.date() <= last.date():
            return False
        if ts.date() == first.date():
            t = first
            while t < last:
                self.preauth_fail(t + timedelta(seconds=self.rng.uniform(0, 20)), "svc_backup",
                                  SERVERS["SQL01"], tag=("btp", "-", "stale service-account password",
                                                         T["guess"]))
                t += timedelta(minutes=15)
            fix = last + timedelta(minutes=12)
            self.tgt(fix, "svc_backup", SERVERS["SQL01"], tag=("btp", "-", "password updated in the job", "-"))
            self.logon(fix + timedelta(seconds=2), "FS01", "svc_backup", 3, SERVERS["SQL01"],
                       tag=("btp", "-", "password updated in the job", "-"))
        return True

    def agent_rollout(self):
        """Aug 12: IT pushes a monitoring agent to every server as a remote service - PsExec's shape."""
        day = datetime(2026, 8, 12, tzinfo=TZ)
        it_ws = self.hosts["WS003"]
        for i, target in enumerate(["FS01", "SQL01", "RDS01", "DC01"]):
            ts = self.at(day, 15 + i * 0.05)
            tag = ("btp", "-", "monitoring agent deployed as a service", T["psexec"])
            self.tgs(ts - timedelta(seconds=1), "adm.it", f"{target}$", it_ws.ip)
            lid = self.logon(ts, target, "adm.it", 3, it_ws.ip, tag=tag, admin=True)
            self.service(ts + timedelta(seconds=3), target, "adm.it", lid, "Zabbix Agent 2",
                         r'"C:\Program Files\Zabbix Agent 2\zabbix_agent2.exe" -c zabbix_agent2.conf', tag)

    # ----------------------------------------------------------- incidents
    def w1_spray(self):
        rng = self.rng
        t = datetime(2026, 7, 14, 22, 10, tzinfo=TZ)
        accounts = [u["login"] for u in self.users] + SPN_ACCOUNTS + ["adm.it", "adm.hd", "adm.backup"]
        invented = ["admin", "test", "guest1", "backup", "scanner", "sqladmin", "webadmin", "user1",
                    "support", "temp", "operator", "info", "service", "manager", "it"]
        order = accounts + invented
        rng.shuffle(order)
        fallen = self.users[5]["login"]
        for name in order:
            t += timedelta(seconds=rng.uniform(12, 25))
            if name == fallen:
                self.tgt(t, name, GUEST_DEVICE, tag=("attack", "W1", "sprayed password works", T["valid"]))
                self.tgs(t + timedelta(seconds=1), name, "DC01$", GUEST_DEVICE,
                         tag=("attack", "W1", "the fallen account queries LDAP", T["valid"]))
                continue
            self.preauth_fail(t, name, GUEST_DEVICE, "0x6" if name in invented else "0x18",
                              ("attack", "W1", "Kerberos password spray", T["spray"]))

    def w2_rdp_brute(self):
        t = datetime(2026, 7, 22, 3, 5, tzinfo=TZ)
        for i in range(800):
            t += timedelta(seconds=self.rng.uniform(1.5, 4.5))
            user = "Administrator" if i % 7 else self.rng.choice(["admin", "administrator", "user", "rdp"])
            self.logon_fail(t, "RDS01", user, 3, INTERNET_BRUTE, "-",
                            "0xc000006a" if user == "Administrator" else "0xc0000064",
                            tag=("attack", "W2", "RDP brute force from the internet", T["guess"]))

    def w3_low_and_slow(self):
        targets = ["Administrator", "adm.it", self.users[1]["login"], self.users[9]["login"]]
        for d in range(5, DAYS - 5):
            day = START + timedelta(days=d)
            for _ in range(3):
                ip = f"{self.rng.choice(SLOW_NETS)}.{self.rng.randrange(2, 250)}"
                self.logon_fail(self.at(day, self.rng.uniform(0, 24)), "RDS01", self.rng.choice(targets), 3, ip,
                                "-", tag=("attack", "W3", "low-and-slow guessing (B5, not in story 5a)",
                                          T["guess"]))

    def w9_distributed(self):
        t = datetime(2026, 8, 28, 2, 10, tzinfo=TZ)
        for _ in range(30):
            ip = f"{self.rng.choice(SLOW_NETS)}.{self.rng.randrange(2, 250)}"
            for _ in range(self.rng.randint(2, 3)):
                t += timedelta(seconds=self.rng.uniform(15, 45))
                self.logon_fail(t, "RDS01", "adm.it", 3, ip, "-",
                                tag=("attack", "W9", "distributed guessing from many addresses", T["guess"]))

    def w4_phish_and_beacon(self):
        u = self.users[22]
        ws, login = u["ws"], u["login"]
        day = datetime(2026, 8, 3, tzinfo=TZ)
        t = day + timedelta(hours=9, minutes=41, seconds=12)
        lid = self.session[(ws, day.date())]
        tag = ("attack", "W4", "phishing attachment runs PowerShell", T["phish"])
        outlook = self.process(t - timedelta(minutes=30), ws, login, lid,
                               r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", '"OUTLOOK.EXE"')
        word = self.process(t, ws, login, lid, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                            r'"WINWORD.EXE" /n "C:\Users\j.duangjai\AppData\Local\Microsoft\Windows\INetCache'
                            r'\Content.Outlook\Q3J8KD2L\Invoice_0803.docm" /o ""', outlook, tag)
        ps = self.process(t + timedelta(seconds=6), ws, login, lid,
                          r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcA"
                          "ZQBiAEMAbABpAGUAbgB0ACkA", word, ("attack", "W4", "encoded PowerShell", T["ps"]))
        dropped = r"C:\Users\j.duangjai\AppData\Roaming\Microsoft\updater.exe"
        self.file_created(t + timedelta(seconds=9), ws, ps, dropped, ("attack", "W4", "payload written", T["ps"]))
        beacon = self.process(t + timedelta(seconds=11), ws, login, lid, dropped, dropped, ps,
                              ("attack", "W4", "payload runs", T["ps"]))
        self.beacon_proc = beacon
        # Every ~5 minutes while the workstation is on, until Sep 20.
        end = datetime(2026, 9, 20, 18, 0, tzinfo=TZ)
        ts = t + timedelta(seconds=40)
        while ts < end:
            local = ts.astimezone(TZ)
            if local.weekday() < 5 and 8 <= local.hour < 18:
                self.connect(ts, ws, beacon, C2, 443, ("attack", "W4", "C2 beacon", T["c2"]))
                ts += timedelta(seconds=300 + self.rng.uniform(-30, 30))
            else:
                nxt = (local + timedelta(days=1)).replace(hour=8, minute=self.rng.randrange(20, 50))
                ts = nxt
        self.attacker_ws = ws

    def w5_kerberoast(self):
        ip = self.users[22]["ip"]
        t = datetime(2026, 8, 10, 14, 2, 7, tzinfo=TZ)
        for a in SPN_ACCOUNTS:
            t += timedelta(seconds=self.rng.uniform(2, 9))
            self.tgs(t, self.users[22]["login"], a, ip, "0x17", ("attack", "W5", "Kerberoasting", T["roast"]))

    def w6_guess_adm_backup(self):
        u = self.users[22]
        t = datetime(2026, 8, 17, 21, 0, 3, tzinfo=TZ)
        tag = ("attack", "W6", "password guessing over NTLM", T["guess"])
        for _ in range(280):
            t += timedelta(seconds=self.rng.uniform(5, 13))
            self.logon_fail(t, "FS01", "adm.backup", 3, u["ip"], u["ws"], tag=tag)
            self.ntlm_check(t + timedelta(milliseconds=self.rng.randrange(1, 400)), "adm.backup", u["ws"],
                            "0xc000006a", tag)
        t += timedelta(seconds=9)
        ok = ("attack", "W6", "guessed password works", T["valid"])
        self.ntlm_check(t, "adm.backup", u["ws"], tag=ok)
        self.logon(t + timedelta(milliseconds=30), "FS01", "adm.backup", 3, u["ip"], u["ws"], "NTLM", ok)

    def w7_rdp_and_lsass(self):
        u = self.users[22]
        t = datetime(2026, 9, 1, 21, 5, 31, tzinfo=TZ)
        tag = ("attack", "W7", "RDP to a server never reached from here", T["rdp"])
        self.tgt(t - timedelta(seconds=4), "adm.backup", u["ip"], tag=tag)
        self.tgs(t - timedelta(seconds=3), "adm.backup", "RDS01$", u["ip"], tag=tag)
        lid = self.logon(t, "RDS01", "adm.backup", 10, u["ip"], "RDS01", "Negotiate", tag, admin=True)
        shell = self.process(t + timedelta(seconds=20), "RDS01", "adm.backup", lid,
                             r"C:\Windows\System32\cmd.exe", '"C:\\Windows\\system32\\cmd.exe"', tag=tag,
                             elevated=True)
        disc = ("attack", "W7", "discovery", T["disc"])
        for i, cmd in enumerate(["whoami /all", 'net group "Domain Admins" /domain', "nltest /dclist:mekong",
                                 "ipconfig /all", "quser"]):
            exe = cmd.split()[0]
            self.process(t + timedelta(seconds=40 + 25 * i), "RDS01", "adm.backup", lid,
                         rf"C:\Windows\System32\{exe}.exe", cmd, shell, disc, elevated=True)
        dump = ("attack", "W7", "LSASS dumped", T["lsass"])
        pd = self.process(t + timedelta(minutes=4), "RDS01", "adm.backup", lid, r"C:\Users\Public\procdump64.exe",
                          r"procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\l.dmp", shell, dump,
                          elevated=True)
        self.lsass_open(t + timedelta(minutes=4, seconds=1), "RDS01", pd, "0x1fffff", dump)
        self.file_created(t + timedelta(minutes=4, seconds=3), "RDS01", pd, r"C:\Users\Public\l.dmp", dump)

    def w8_pth_and_psexec(self):
        u = self.users[22]
        t = datetime(2026, 9, 2, 20, 30, 12, tzinfo=TZ)
        tag = ("attack", "W8", "pass-the-hash: NTLM logon, no Kerberos", T["pth"])
        sessions = {}
        for target in ["FS01", "SQL01", "DC01"]:
            t += timedelta(seconds=self.rng.uniform(20, 60))
            self.ntlm_check(t, "adm.it", u["ws"], tag=tag)
            sessions[target] = self.logon(t + timedelta(milliseconds=20), target, "adm.it", 3, u["ip"], u["ws"],
                                          "NTLM", tag, admin=True)
        t += timedelta(minutes=3)
        svc = ("attack", "W8", "PsExec-style service in the stolen session", T["psexec"])
        self.service(t, "SQL01", "adm.it", sessions["SQL01"], "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe", svc)
        services = {"image": r"C:\Windows\System32\services.exe", "pid": 680, "guid": self.guid("SQL01"),
                    "cmd": r"C:\Windows\system32\services.exe", "user": "NT AUTHORITY\\SYSTEM"}
        psexesvc = self.process(t + timedelta(seconds=1), "SQL01", "NT AUTHORITY\\SYSTEM", "0x3e7",
                                r"C:\Windows\PSEXESVC.exe", r"C:\Windows\PSEXESVC.exe", services, svc,
                                elevated=True)
        cmd = self.process(t + timedelta(seconds=2), "SQL01", "NT AUTHORITY\\SYSTEM", "0x3e7",
                           r"C:\Windows\System32\cmd.exe", "cmd.exe", psexesvc, svc, elevated=True)
        self.process(t + timedelta(seconds=30), "SQL01", "NT AUTHORITY\\SYSTEM", "0x3e7",
                     r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE",
                     'sqlcmd -S . -Q "BACKUP DATABASE ERP TO DISK=\'C:\\Users\\Public\\erp.bak\'"', cmd, svc,
                     elevated=True)

    # ----------------------------------------------------------- the quarter
    def build(self):
        self.session = {}
        self.lsass_guid = {n: self.guid(n) for n in SERVERS}
        self.av_guid = {n: self.guid(n) for n in SERVERS}
        for d in range(DAYS):
            day = START + timedelta(days=d)
            workday = day.weekday() < 5
            self.machine_day(day)
            self.defender(day)
            self.admin_day(day)
            for u in self.users:
                before = len(self.events)
                self.user_day(day, u, workday)
                for ev in self.events[before:]:
                    if ev[1] == u["ws"] and ev[3] == 4624 and ev[4][8][1] == "2":
                        self.session[(u["ws"], day.date())] = ev[4][7][1]
                        break
        self.agent_rollout()
        self.w1_spray()
        self.w2_rdp_brute()
        self.w3_low_and_slow()
        self.w9_distributed()
        if (self.users[22]["ws"], datetime(2026, 8, 3).date()) not in self.session:
            # The phished user came in that Monday: make sure there is a session to run in.
            self.user_day(datetime(2026, 8, 3, tzinfo=TZ), self.users[22], True)
            for ev in reversed(self.events):
                if ev[1] == self.users[22]["ws"] and ev[3] == 4624:
                    self.session[(self.users[22]["ws"], datetime(2026, 8, 3).date())] = ev[4][7][1]
                    break
        self.w4_phish_and_beacon()
        self.w5_kerberoast()
        self.w6_guess_adm_backup()
        self.w7_rdp_and_lsass()
        self.w8_pth_and_psexec()


def render(host: Host, channel: str, eid: int, rec: int, ts, data, failure: bool) -> str:
    if channel == "Security":
        prov, guid = SEC_PROVIDER
        task, kw, sec = TASK.get(eid, 0), (FAIL_KW if failure else OK_KW), "<Security/>"
        version = {4624: 2, 4625: 0, 4688: 2, 4768: 0, 4769: 0}.get(eid, 0)
        execution = "<Execution ProcessID='716' ThreadID='%d'/>" % (4000 + rec % 3000)
    else:
        prov, guid = SYS_PROVIDER
        task, kw, sec = SYSMON_TASK.get(eid, 0), "0x8000000000000000", "<Security UserID='S-1-5-18'/>"
        version = {1: 5, 3: 5, 10: 3, 11: 2}.get(eid, 0)
        execution = "<Execution ProcessID='2880' ThreadID='%d'/>" % (3000 + rec % 2000)
    items = "".join(f"<Data Name='{n}'>{escape(v)}</Data>" for n, v in data)
    return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            f"<Provider Name='{prov}' Guid='{guid}'/><EventID>{eid}</EventID><Version>{version}</Version>"
            f"<Level>{4 if channel != 'Security' else 0}</Level><Task>{task}</Task><Opcode>0</Opcode>"
            f"<Keywords>{kw}</Keywords><TimeCreated SystemTime='{system_time(ts)}'/>"
            f"<EventRecordID>{rec}</EventRecordID><Correlation/>{execution}<Channel>{channel}</Channel>"
            f"<Computer>{host.fqdn}</Computer>{sec}</System><EventData>{items}</EventData></Event>")


README = """# Mekong Parts - a synthetic Windows quarter

Written by `tests/gen_windows_domain.py` (seed {seed}). Fictitious domain MEKONG.LOCAL, 2026-07-01 to
2026-09-30, GMT+7. One event XML file per host and channel; `mekong-windows-2026Q3.zip` is all of
them as one case. Every event that is not plain work is in `ground_truth.csv` with its label.

{incidents}

## Look-alikes (label `lookalike` - a finding on one is a false positive)

- adm.it on RDP to RDS01 / SQL01 / FS01 two or three times a week, running PowerShell, cmd and MMC
  (W7's shape, from WS003, a pair seen all quarter).
- Six finance users ask DC01 for an RC4 ticket to `svc_legacy` every working day (W5's encryption,
  one service each).
- Defender (MsMpEng.exe) opens lsass.exe on every server daily, access 0x1010, writes nothing (W7's
  dump without the dump).
- The second-floor scanner signs in to FS01 over NTLM as `svc_scan` all day and never uses Kerberos
  (W8's NTLM-without-Kerberos).
- OneDrive syncs every two hours to one Microsoft address (a regular connection to a public address).
- DC01's own machine account signs in to DC01 from its address, 127.0.0.1 and ::1 (one account,
  several sources).
- Users mistype a password (4625 on the workstation + 4771 on DC01, same attempt), then sign in.

## Benign true positives (label `btp` - a finding the analyst closes as benign is right)

- Aug 25-27: `svc_backup`'s password changed, the job on SQL01 kept the old one - a failure every
  15 minutes for two days, then fixed.
- Aug 12: IT deploys Zabbix Agent 2 to every server as a remote service (PsExec's shape).
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outdir")
    ap.add_argument("--seed", type=int, default=20260701)
    args = ap.parse_args()
    out = pathlib.Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)

    g = Gen(args.seed)
    g.build()
    events = sorted(enumerate(g.events), key=lambda x: (x[1][0], x[0]))
    files, truth = {}, []
    handles = {}
    record = {}
    try:
        for _, (ts, host, channel, eid, data, failure, tag) in events:
            key = (host, channel)
            name = f"{host}-{'Security' if channel == 'Security' else 'Sysmon'}.xml"
            if key not in handles:
                handles[key] = open(out / name, "w", encoding="utf-8", newline="\n")
                files[key] = out / name
                record[key] = g.rng.randrange(20000, 900000)
            record[key] += 1
            handles[key].write(render(g.hosts[host], channel, eid, record[key], ts, data, failure) + "\n")
            if tag:
                label, inc, stage, tech = tag
                truth.append((name, host, channel, record[key], ts.astimezone(TZ).strftime("%Y-%m-%d %H:%M:%S"),
                              eid, label, inc, stage, tech))
    finally:
        for fh in handles.values():
            fh.close()
    with open(out / "ground_truth.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "host", "channel", "record_id", "time_gmt7", "event_id", "label", "incident",
                    "stage", "technique"])
        w.writerows(sorted(truth, key=lambda r: (r[4], r[0], r[3])))
    incidents = "\n".join(line[2:] for line in __doc__.split("Incidents")[1].split("Nothing here")[0]
                          .splitlines()[1:] if line.strip())
    (out / "README.md").write_text(README.format(seed=args.seed, incidents="## Incidents\n\n```\n"
                                                 + incidents + "\n```"), encoding="utf-8")
    zpath = out / "mekong-windows-2026Q3.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(files.values()):
            z.write(path, path.name)
    total = sum(p.stat().st_size for p in files.values())
    print(f"{len(files)} files, {len(events):,} events, {total / 1e6:.1f} MB; "
          f"{zpath.name}: {zpath.stat().st_size / 1e6:.1f} MB; ground_truth.csv: {len(truth):,} rows")


if __name__ == "__main__":
    main()
