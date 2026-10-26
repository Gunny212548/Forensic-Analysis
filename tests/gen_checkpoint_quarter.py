"""Generate three months of Check Point logs with real-world attacks buried in an office's traffic.

    python tests/gen_checkpoint_quarter.py <outdir> [--seed N]

Format: Check Point Log Exporter records (default syslog format) inside a
ManageEngine EventLog Analyzer search export - the layout of the customer's real
export (D:/logtest/Check point/, gotcha #59), read by
app/services/checkpoint_le.py. EventLog Analyzer writes the newest row first,
and so does this. One file per month, and a zip of the three, which is one case
- so rules and the timeline see the whole quarter at once.

Writes, for the fictitious "Lotus Freight" (~140 staff, GMT+7, 2026-07-01 ..
2026-09-30):

  lotus-checkpoint-2026-07.csv   July
  lotus-checkpoint-2026-08.csv   August
  lotus-checkpoint-2026-09.csv   September
  lotus-checkpoint-2026Q3.zip    the three above (= one case)
  ground_truth.csv               file, row #, time, loguid, label, incident,
                                 stage, ATT&CK technique for every row that is
                                 not plain benign traffic

The attacks are modelled on publicly reported ones (see the README written
next to the files):
  I1 Jul 9      one botnet node sweeps ~650 services of the gateway, mostly
                dropped, accepted by implied rules on 443 / 18264 / 500 (the
                customer's own Jun 2026 SOC case, "Firewall Port Scanning &
                Implied Rule Bypass")
  I2 Jul 20 -> Sep 27  the long chain: mass scanning for CVE-2024-24919, the
                gateway file read, a stale local VPN account used to log in,
                internal discovery, RDP to the terminal server, re-entries in
                August, a 5-minute C2 beacon for six weeks, rclone-style
                exfiltration to MEGA on Sep 26, SMB spread and encryption on
                Sep 27 (the encrypted hosts fall silent)
  I3 Aug 4-6    password spray against the Remote Access VPN from ~190 proxy
                addresses (the 2024 mass VPN brute-force campaigns); nothing
                succeeds
  I4 Aug 18     QakBot-style infection of one workstation: download, C2 on
                443/995/2222, SMB sweep of the server VLAN, then contained
  I5 all quarter  Log4Shell probes against the DMZ web server, prevented by
                IPS; on Aug 27 one passes and the server's LDAP callback is
                dropped by the DMZ outbound rule
  I6 Sep 3      SSH brute force against the published SFTP server - the
                firewall sees only connection volume

Also labelled, because they are not the incident but are not plain benign
either: "background-scan" (internet research scanners refused at the
perimeter), "benign-periodic" (a monitoring proxy reporting to its cloud
server every 15 minutes, which is what a beacon looks like - gotcha #15) and
"benign-large-upload" (staff syncing large files to OneDrive, over R3001's
50 MB line).

Everything is drawn from one seeded RNG, so the same seed reproduces the same
files byte for byte. Attacker and third-party infrastructure is in the RFC 5737
documentation ranges (198.51.100.0/24 attackers, 192.0.2.0/24 partners, the
company's own public block 203.0.113.10-12, the spray pool 203.0.113.100-250),
so no real host is accused. Internet scanners come from the published ranges
of research scanners (Censys, Shadowserver, Palo Alto Xpanse) - real scanners,
correctly called scanners. SaaS destinations are real-looking public addresses
of the named services; with threat-intel feeds loaded one can match a feed.

Field names and values follow sk144192 and the customer's export. Record types
the customer's export does not contain (IPS, Anti-Bot, Remote Access VPN
sign-ins) are modelled on sk144192 field names, not copied from a capture.
"""
import argparse
import csv
import pathlib
import random
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

TZ = timezone(timedelta(hours=7))
START = datetime(2026, 7, 1, tzinfo=TZ)   # Wednesday
DAYS = 92                                 # to 2026-09-30 inclusive

# ------------------------------------------------------------------ the site
GW = "192.168.1.1"                        # the gateway: Log Exporter `origin`
GW_SIC = "CN=LF-GW01,O=LF-MGMT..k3v9qa"
ELA_DEVICE = "192.168.1.5"                # the management server EventLog Analyzer collects from
PUB_GW, PUB_WEB, PUB_SFTP = "203.0.113.10", "203.0.113.11", "203.0.113.12"
DC1, DC2, FS, ERP, RDS, MONITOR = ("192.168.20.10", "192.168.20.11", "192.168.20.20",
                                   "192.168.20.30", "192.168.20.25", "192.168.20.70")
SERVERS = [DC1, DC2, FS, ERP, RDS, MONITOR, "192.168.20.40", "192.168.20.50", "192.168.20.60"]
WEB_DMZ, SFTP_DMZ = "172.16.50.10", "172.16.50.20"
BRANCH_PEER = "192.0.2.50"                # site-to-site VPN peer
SFTP_PARTNERS = ["192.0.2.60", "192.0.2.61"]
ZABBIX_CLOUD = "192.0.2.80"
RESOLVERS = ["8.8.8.8", "1.1.1.1"]

# Attacker infrastructure (RFC 5737).
I1_SWEEPER = "198.51.100.66"
I2_SCANNERS = [f"198.51.100.{n}" for n in range(200, 206)]
I2_ACTOR = "198.51.100.23"
I2_REENTRY = ["198.51.100.23", "198.51.100.41", "198.51.100.41", "198.51.100.23", "198.51.100.41"]
I2_C2 = "198.51.100.45"
I2_EXFIL = "198.51.100.88"
I2_VPN_IP = "10.255.10.21"                # Office Mode address the stale account receives
I3_POOL = [f"203.0.113.{n}" for n in range(100, 251)] + [f"198.51.100.{n}" for n in range(160, 200)]
I4_DROPPER, I4_C2 = "198.51.100.140", ["198.51.100.141", "198.51.100.142", "198.51.100.143"]
I5_PROBES = [f"198.51.100.{n}" for n in range(210, 231)]
I5_CALLBACK = "198.51.100.150"
I6_BRUTE = "198.51.100.33"

# Published research-scanner ranges (Censys, Shadowserver, Palo Alto Xpanse).
SCANNER_NETS = ["162.142.125", "167.94.138", "167.94.146", "206.168.34", "184.105.139",
                "74.82.47", "65.49.1", "205.210.31", "198.235.24"]
SCAN_PORTS = [22, 23, 80, 443, 445, 3389, 8080, 5900, 1433, 3306, 6379, 9200, 8443, 21, 25,
              5060, 2323, 7547, 8291, 37215, 52869, 81, 8000, 8888, 554, 161, 1900, 11211]
TH_ISP_NETS = ["171.96", "171.97", "184.22", "49.228", "49.229", "58.8", "58.9", "110.164",
               "1.46", "125.24", "180.183", "223.24"]

# (domain, address prefix, port, app name) - SaaS a logistics office uses.
SAAS = [
    ("outlook.office365.com", "52.97.146", 443, "Outlook Web Access"),
    ("teams.microsoft.com", "52.113.194", 443, "Microsoft Teams"),
    ("login.microsoftonline.com", "20.190.144", 443, "Microsoft Authentication"),
    ("graph.microsoft.com", "20.190.151", 443, "Microsoft Graph"),
    ("onedrive.live.com", "13.107.42", 443, "Microsoft OneDrive"),
    ("www.google.com", "142.250.199", 443, "Google Search"),
    ("mail.google.com", "142.250.204", 443, "Gmail"),
    ("line.me", "147.92.146", 443, "LINE"),
    ("www.facebook.com", "157.240.13", 443, "Facebook"),
    ("www.youtube.com", "142.250.66", 443, "YouTube"),
    ("s3.ap-southeast-1.amazonaws.com", "52.219.32", 443, "Amazon S3"),
    ("crl3.digicert.com", "23.11.38", 80, "HTTP Protocol"),
    ("ctldl.windowsupdate.com", "23.39.8", 80, "Windows Update"),
    ("api.dhl.com", "165.72.212", 443, "DHL"),
    ("www.bot.or.th", "203.150.230", 443, "HTTPS Protocol"),
]
SAAS_WEIGHTS = [16, 10, 8, 5, 6, 10, 4, 9, 5, 4, 3, 3, 3, 6, 2]
MEDIA = [("open.spotify.com", "35.186.224", "Spotify"), ("www.tiktok.com", "23.48.200", "TikTok"),
         ("www.netflix.com", "52.94.230", "Netflix")]

SERVICE_ID = {443: "https", 80: "http", 53: "domain-udp", 445: "microsoft-ds", 389: "ldap",
              88: "Kerberos_v5_TCP", 135: "ALL_DCE_RPC", 3389: "Remote_Desktop_Protocol",
              22: "ssh_version_2", 1433: "MS-SQL-Server", 5985: "winrm", 18264: "FW1_ica_services",
              500: "IKE", 4500: "IKE_NAT_TRAVERSAL", 10051: "zabbix-trapper", 23: "telnet",
              21: "ftp", 25: "smtp", 3306: "mysql", 8080: "http_proxy", 995: "pop3s", 2222: "tcp-2222",
              1389: "tcp-1389"}
PROTOCOL = {443: "HTTPS", 80: "HTTP", 53: "DNS", 445: "SMB", 389: "LDAP", 3389: "RDP", 22: "SSH"}

FIRST = ["Somchai", "Suda", "Anan", "Pornthip", "Kittisak", "Nattaya", "Wichai", "Siriporn",
         "Prasert", "Kanya", "Thanakorn", "Waraporn", "Chaiwat", "Jiraporn", "Narong", "Ratana",
         "Surasak", "Duangjai", "Yuthana", "Supaporn", "Ekkachai", "Malee", "Pichit", "Orawan",
         "Teerapong", "Kulthida", "Apichat", "Sasithorn", "Boonmee", "Nittaya", "Pakorn", "Rungnapa",
         "Sakda", "Usa", "Weerachai", "Lamai", "Thawatchai", "Benjawan", "Sombat", "Chanida"]
LAST = ["Srisuk", "Wongsa", "Chaiyaporn", "Kaewmanee", "Thongdee", "Rattanakul", "Saetang",
        "Boonyarat", "Phromma", "Inthong", "Suwan", "Charoen", "Pongsiri", "Kongkaew", "Siriwat"]
OUS = ["OPS", "ACC", "SALE", "HR", "IT", "WH", "CS"]

# rule key -> (match_id, rule name, rule action)
RULES = {
    "implied": ("0", "Implied Rule", "Accept"),
    "internet": ("10", "Internet Access", "Accept"),
    "media": ("11", "Block Media (Interns)", "Drop"),
    "dns": ("20", "DC DNS Forwarders", "Accept"),
    "servers": ("30", "Users to Servers", "Accept"),
    "smb_vlan": ("31", "Block SMB between VLANs", "Drop"),
    "ra": ("40", "Remote Access to Servers", "Accept"),
    "web": ("50", "DMZ Web Published", "Accept"),
    "sftp": ("51", "SFTP Partners", "Accept"),
    "dmz_out": ("52", "DMZ Outbound Deny", "Drop"),
    "monitor": ("60", "Monitoring to Cloud", "Accept"),
    "srv_out": ("70", "Servers to Internet", "Accept"),
    "it_smb": ("80", "IT Management SMB", "Accept"),
    "cleanup": ("99", "Cleanup rule", "Drop"),
}
FLAGS = ["409600", "278544", "400644", "8150288", "8279040", "8147968", "6422528", "394240"]
HEAD_KEYS = {"action", "conn_direction", "contextnum", "flags", "ifdir", "ifname", "logid", "loguid",
             "origin", "originsicname", "sequencenum", "time", "version"}
# Policy installs: the incidents change the policy (QakBot -> SMB blocked from
# workstations is already there; after I2 the stale account rule is removed).
POLICY_INSTALLS = [datetime(2026, 6, 18, 17, 40, tzinfo=TZ), datetime(2026, 8, 19, 18, 5, tzinfo=TZ),
                   datetime(2026, 9, 29, 21, 30, tzinfo=TZ)]

# One technique per stage, as the analyst would tag it.
T = {
    "scan-ext": "T1595.001", "exploit-public": "T1190", "valid-account": "T1078",
    "ext-remote": "T1133", "discovery": "T1046", "rdp": "T1021.001", "tool-transfer": "T1105",
    "c2-web": "T1071.001", "c2-port": "T1571", "exfil-cloud": "T1567.002", "smb": "T1021.002",
    "impact": "T1486", "spray": "T1110.003", "brute": "T1110.001", "phish-link": "T1204.001",
}


class Gen:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.events = []          # (ts, fields, tag)
        self.counter = 0
        self.origin_hex = "0x" + "".join(f"{int(o):02x}" for o in reversed(GW.split("."))).lstrip("0")
        self.rule_uid = {k: str(uuid.UUID(int=self.rng.getrandbits(128), version=4)) for k in RULES}
        self.layer_uuid = str(uuid.UUID(int=self.rng.getrandbits(128), version=4))
        self.db_tag = str(uuid.UUID(int=self.rng.getrandbits(128), version=4)).upper()
        self.silent: dict[str, list[tuple[datetime, datetime]]] = {}
        self.users = self._users()

    # ----------------------------------------------------------- primitives
    def _users(self):
        rng, out, seen = self.rng, [], set()
        for i in range(140):
            while True:
                first, last = rng.choice(FIRST), rng.choice(LAST)
                login = f"{first.lower()}.{last[0].lower()}"
                if login not in seen:
                    seen.add(login)
                    break
            # 10.11-10.250 office, 11.x warehouse, 12.x interns
            ip = (f"192.168.10.{11 + i}" if i < 90 else
                  f"192.168.11.{11 + i - 90}" if i < 132 else f"192.168.12.{11 + i - 132}")
            ou = "INTERN" if i >= 132 else ("WH" if i >= 90 else rng.choice(OUS))
            out.append({"ip": ip, "login": login, "name": f"{first} {last}", "ou": ou,
                        "intern": i >= 132})
        return out

    def user_fields(self, u) -> dict:
        label = f"{u['name']} ({u['login']}) "
        return {"src_machine_name": f"lf-{u['login']}@lotusfreight.local",
                "src_user_dn": f"CN={u['name']},OU={u['ou']},OU=LF-Users,DC=lotusfreight,DC=local ",
                "src_user_name": label, "user": label}

    def loguid(self, ts: datetime) -> str:
        self.counter += 1
        return (f"{{0x{int(ts.timestamp()):x},0x{self.counter & 0xffff:x},{self.origin_hex},"
                f"0x{self.rng.getrandbits(32):x}}}")

    def policy_tag(self, ts: datetime) -> str:
        installed = max(p for p in POLICY_INSTALLS if p <= ts)
        return (f"product=VPN-1 & FireWall-1[db_tag={{{self.db_tag}}};mgmt=LF-MGMT;"
                f"date={int(installed.timestamp())};policy_name=Standard]")

    def is_silent(self, ip: str, ts: datetime) -> bool:
        return any(a <= ts < b for a, b in self.silent.get(ip, ()))

    def emit(self, ts: datetime, fields: dict, tag=None, loguid=None, seq=None) -> str:
        lu = loguid or self.loguid(ts)
        f = {"flags": self.rng.choice(FLAGS), "ifdir": "inbound", "loguid": lu, "origin": GW,
             "originsicname": GW_SIC, "sequencenum": str(seq or self.rng.randint(1, 40)),
             "time": str(int(ts.timestamp())), "version": "5"}
        f.update(fields)
        self.events.append((ts, f, tag))
        return lu

    def conn(self, ts, src, dst, port, rule, *, proto="6", action=None, product="VPN-1 & FireWall-1",
             domain=None, user=None, xlatesrc=None, xlatedst=None, inzone="Internal",
             outzone="External", app=None, extra=None, tag=None, update=None) -> str:
        """One connection log; `update` = (seconds, client_out_bytes, server_out_bytes) adds the
        update log Log Exporter writes for the same loguid when the connection ends."""
        mid, rname, raction = RULES[rule]
        f = {"action": action or raction, "conn_direction": "Outgoing" if outzone == "External" else
             ("Incoming" if inzone == "External" else "Internal"),
             "contextnum": "1", "ifname": "eth1" if inzone == "Internal" else "eth0", "logid": "0",
             "__policy_id_tag": self.policy_tag(ts), "dst": dst, "inzone": inzone, "outzone": outzone,
             "layer_name": "Network", "layer_uuid": self.layer_uuid, "match_id": mid, "parent_rule": "0",
             "rule_action": raction, "rule_name": rname, "rule_uid": self.rule_uid[rule],
             "product": product, "proto": proto, "s_port": str(self.rng.randint(1025, 65535)),
             "service": str(port), "service_id": SERVICE_ID.get(port, f"{'udp' if proto == '17' else 'tcp'}-{port}"),
             "src": src}
        if port in PROTOCOL:
            f["protocol"] = PROTOCOL[port]
        if domain:
            f["destination_domain_name"] = domain
            if port == 443:
                f["sni"] = f["tls_server_host_name"] = domain
        if app:
            f["appi_name"] = app
        if xlatesrc:
            f.update(xlatesrc=xlatesrc, xlatesport=str(self.rng.randint(10000, 40000)),
                     xlatedst="0.0.0.0", xlatedport="0", nat_rulenum="50", nat_addtnl_rulenum="0")
        if xlatedst:
            f.update(xlatedst=xlatedst, xlatedport=str(port), xlatesrc="0.0.0.0", nat_rulenum="12",
                     nat_addtnl_rulenum="0")
        if user:
            f.update(self.user_fields(user))
        if extra:
            f.update(extra)
        seq = self.rng.randint(1, 30)
        lu = self.emit(ts, f, tag, seq=seq)
        if update and f["action"] == "Accept":
            secs, c_out, s_out = update
            end = ts + timedelta(seconds=secs)
            u = {k: f[k] for k in ("action", "conn_direction", "contextnum", "ifname", "logid",
                                   "__policy_id_tag", "dst", "product", "proto", "s_port", "service",
                                   "service_id", "src")}
            for k in ("src_machine_name", "src_user_dn", "src_user_name", "user", "xlatesrc",
                      "destination_domain_name"):
                if k in f:
                    u[k] = f[k]
            c_pk, s_pk = max(1, c_out // 1300), max(1, s_out // 1300)
            u.update(lastupdatetime=str(int(end.timestamp())), creation_time=str(int(ts.timestamp())),
                     duration=str(secs), elapsed=str(secs), client_outbound_bytes=str(c_out),
                     client_inbound_bytes=str(s_out), server_inbound_bytes=str(c_out),
                     server_outbound_bytes=str(s_out), client_outbound_packets=str(c_pk),
                     client_inbound_packets=str(s_pk), bytes=str(c_out + s_out),
                     packets=str(c_pk + s_pk), segment_time=str(int(end.timestamp())),
                     aggregated_log_count="1", connection_count="1", update_count="1")
            self.emit(end, u, tag, loguid=lu, seq=seq + 1)
        return lu

    def outbound(self, ts, u, domain, prefix, port, app, rule="internet", tag=None, big=None):
        dst = f"{prefix}.{self.rng.choice((14, 35, 78, 110, 142, 196))}"
        upd = None
        if big:
            upd = big
        elif self.rng.random() < 0.2:
            upd = (self.rng.randint(1, 600), self.rng.randint(800, 400_000), self.rng.randint(2_000, 4_000_000))
        return self.conn(ts, u["ip"], dst, port, rule, domain=domain, user=u, xlatesrc=PUB_GW, app=app,
                         tag=tag, update=upd)

    def vpn_login(self, ts, src, account, ok: bool, office_ip=None, tag=None, dn=None):
        f = {"action": "Log In" if ok else "Failed Log In", "ifname": "eth0", "logid": "131073",
             "__policy_id_tag": self.policy_tag(ts), "product": "VPN-1 & FireWall-1",
             "fw_subproduct": "VPN-1", "vpn_feature_name": "Remote Access", "auth_method": "Password",
             "auth_status": "Successful Login" if ok else "Failed Login", "src": src, "dst": PUB_GW,
             "proto": "6", "service": "443", "s_port": str(self.rng.randint(1025, 65535)),
             "user": account, "src_user_name": account, "client_name": "Endpoint Security VPN",
             "client_version": "E88.30", "os_name": "Windows"}
        if dn:
            f["src_user_dn"] = dn
        if ok:
            f["office_mode_ip"] = office_ip
        else:
            f["reason"] = "Wrong user name or password"
        return self.emit(ts, f, tag)

    def ips(self, ts, src, dst, port, action, attack, info, cve, resource, xlatedst=None, tag=None,
            method="POST"):
        f = {"action": action, "ifname": "eth0", "__policy_id_tag": self.policy_tag(ts), "product": "IPS",
             "attack": attack, "attack_info": info, "protection_name": attack,
             "protection_id": f"asm_dynamic_prop_{cve.replace('-', '_')}", "protection_type": "IPS",
             "industry_reference": cve, "severity": "Critical", "confidence_level": "High",
             "performance_impact": "Low", "resource": resource, "method": method, "src": src, "dst": dst,
             "proto": "6", "service": str(port), "s_port": str(self.rng.randint(1025, 65535))}
        if xlatedst:
            f["xlatedst"] = xlatedst
        return self.emit(ts, f, tag)

    def antibot(self, ts, src, dst, port, action, family, protection, domain, user=None, tag=None):
        f = {"action": action, "ifname": "eth1", "__policy_id_tag": self.policy_tag(ts), "product": "Anti-Bot",
             "protection_name": protection, "malware_family": family,
             "malware_action": "Communication with C&C site", "protection_type": "Reputation IP",
             "severity": "Critical", "confidence_level": "High", "resource": f"https://{domain}/",
             "src": src, "dst": dst, "proto": "6", "service": str(port),
             "s_port": str(self.rng.randint(1025, 65535))}
        if user:
            f.update(self.user_fields(user))
        return self.emit(ts, f, tag)

    # ----------------------------------------------------------- background
    def background(self):
        rng = self.rng
        vpn_staff = [u for u in self.users if u["ou"] == "ACC"][:5]
        vpn_home = {u["login"]: f"{rng.choice(TH_ISP_NETS)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
                    for u in vpn_staff}
        for day in range(DAYS):
            d0 = START + timedelta(days=day)
            weekday = d0.weekday() < 5
            for u in self.users:
                if rng.random() > (0.93 if weekday else 0.05):
                    continue
                login = d0 + timedelta(hours=8, minutes=rng.randint(0, 75), seconds=rng.randint(0, 59))
                if self.is_silent(u["ip"], login):
                    continue
                self.emit(login, {"action": "Log In", "ifname": "eth1", "logid": "131073",
                                  "product": "Identity Awareness", "identity_src": "Identity Collector",
                                  "identity_type": "user", "auth_method": "Identity Collector",
                                  "auth_status": "Successful Login", "src": u["ip"],
                                  **self.user_fields(u)})
                for _ in range(rng.randint(4, 9) if weekday else rng.randint(1, 3)):
                    ts = login + timedelta(seconds=rng.randint(0, 9 * 3600))
                    if self.is_silent(u["ip"], ts):
                        continue
                    r = rng.random()
                    if r < 0.55:
                        dom, pre, port, app = rng.choices(SAAS, SAAS_WEIGHTS)[0]
                        self.outbound(ts, u, dom, pre, port, app)
                    elif r < 0.65:
                        self.conn(ts, u["ip"], rng.choice((DC1, DC2)), rng.choice((389, 88, 445, 135)),
                                  "servers", user=u, outzone="Servers")
                    elif r < 0.78:
                        self.conn(ts, u["ip"], FS, 445, "servers", user=u, outzone="Servers",
                                  update=(rng.randint(5, 1800), rng.randint(2_000, 8_000_000),
                                          rng.randint(10_000, 30_000_000)))
                    elif r < 0.88:
                        self.conn(ts, u["ip"], ERP, rng.choice((443, 1433)), "servers", user=u,
                                  outzone="Servers")
                    elif r < 0.93 and u["intern"]:
                        dom, pre, app = rng.choice(MEDIA)
                        self.conn(ts, u["ip"], f"{pre}.{rng.randint(2, 60)}", 443, "media",
                                  product="Application Control", domain=dom, user=u, app=app,
                                  xlatesrc=PUB_GW, extra={"app_category": "Media Streams",
                                                          "app_risk": "2"})
                    else:
                        dom, pre, port, app = rng.choices(SAAS, SAAS_WEIGHTS)[0]
                        self.outbound(ts, u, dom, pre, port, app)
            # weekly: someone syncs a big folder to OneDrive (over R3001's 50 MB line)
            if d0.weekday() == 2:
                u = rng.choice(self.users[:90])
                ts = d0 + timedelta(hours=rng.randint(10, 16), minutes=rng.randint(0, 59))
                self.outbound(ts, u, "onedrive.live.com", "13.107.42", 443, "Microsoft OneDrive",
                              tag=("benign-large-upload", "", "OneDrive sync", ""),
                              big=(rng.randint(400, 1800), rng.randint(55_000_000, 140_000_000),
                                   rng.randint(200_000, 900_000)))
            # domain controllers forward DNS
            for dc in (DC1, DC2):
                for _ in range(rng.randint(90, 140) if weekday else rng.randint(30, 50)):
                    ts = d0 + timedelta(seconds=rng.randint(0, 86399))
                    if not self.is_silent(dc, ts):
                        self.conn(ts, dc, rng.choice(RESOLVERS), 53, "dns", proto="17", xlatesrc=PUB_GW,
                                  outzone="External", inzone="Servers")
            # servers fetch updates
            for srv in (DC1, DC2, FS, ERP, RDS):
                for _ in range(rng.randint(1, 3)):
                    ts = d0 + timedelta(seconds=rng.randint(0, 86399))
                    if not self.is_silent(srv, ts):
                        self.conn(ts, srv, f"23.39.8.{rng.randint(2, 250)}", rng.choice((80, 443)),
                                  "srv_out", domain="ctldl.windowsupdate.com", xlatesrc=PUB_GW,
                                  inzone="Servers")
            # customers on the tracking portal
            for _ in range(rng.randint(80, 160) if weekday else rng.randint(30, 60)):
                ts = d0 + timedelta(seconds=rng.randint(6 * 3600, 23 * 3600))
                src = f"{rng.choice(TH_ISP_NETS)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
                self.conn(ts, src, PUB_WEB, 443, "web", xlatedst=WEB_DMZ, inzone="External", outzone="DMZ",
                          domain="track.lotusfreight.example",
                          update=(rng.randint(2, 120), rng.randint(1_000, 30_000), rng.randint(20_000, 900_000)))
            # partners' nightly SFTP drops
            if weekday:
                for p in SFTP_PARTNERS:
                    ts = d0 + timedelta(hours=rng.choice((1, 23)), minutes=rng.randint(0, 20),
                                        seconds=rng.randint(0, 59))
                    self.conn(ts, p, PUB_SFTP, 22, "sftp", xlatedst=SFTP_DMZ, inzone="External", outzone="DMZ",
                              update=(rng.randint(5, 90), rng.randint(50_000, 9_000_000), rng.randint(3_000, 9_000)))
            # site-to-site key exchange with the branch, about every 8 hours
            for h in (2, 10, 18):
                ts = d0 + timedelta(hours=h, minutes=rng.randint(0, 25), seconds=rng.randint(0, 59))
                self.emit(ts, {"action": "Key Install", "ifname": "daemon", "community": "LF-Branch",
                               "fw_subproduct": "VPN-1", "vpn_feature_name": "IKE", "peer_gateway": BRANCH_PEER,
                               "scheme:": "IKEv2", "src": GW, "dst": BRANCH_PEER,
                               "cookiei": f"{rng.getrandbits(64):016x}", "cookier": f"{rng.getrandbits(64):016x}",
                               "ike:": "Main Mode completion."})
            # finance staff on the Remote Access VPN, to the terminal server
            if weekday:
                for i, u in enumerate(vpn_staff):
                    if rng.random() < 0.6:
                        ts = d0 + timedelta(hours=rng.choice((7, 19, 20)), minutes=rng.randint(0, 59))
                        oip = f"10.255.10.{50 + i}"
                        self.vpn_login(ts, vpn_home[u["login"]], f"{u['name']} ({u['login']}) ", True, oip,
                                       dn=self.user_fields(u)["src_user_dn"])
                        self.conn(ts + timedelta(seconds=rng.randint(20, 90)), oip, RDS, 3389, "ra",
                                  inzone="VPN", outzone="Servers",
                                  update=(rng.randint(600, 7200), rng.randint(2_000_000, 15_000_000),
                                          rng.randint(20_000_000, 90_000_000)))
            # the monitoring proxy reports to its cloud server every 15 minutes
            t = d0 + timedelta(seconds=rng.randint(0, 60))
            while t < d0 + timedelta(days=1):
                self.conn(t, MONITOR, ZABBIX_CLOUD, 10051, "monitor", xlatesrc=PUB_GW, inzone="Servers",
                          domain="zbx.lotusfreight-cloud.example",
                          tag=("benign-periodic", "", "Zabbix proxy heartbeat", ""))
                t += timedelta(seconds=900 + rng.randint(-20, 20))
            # internet research scanners refused at the perimeter
            for _ in range(rng.randint(90, 170)):
                ts = d0 + timedelta(seconds=rng.randint(0, 86399))
                src = f"{rng.choice(SCANNER_NETS)}.{rng.randint(1, 254)}"
                port = rng.choice(SCAN_PORTS)
                self.conn(ts, src, rng.choice((PUB_GW, PUB_WEB, PUB_SFTP)), port, "cleanup",
                          proto="17" if port in (161, 1900, 5060) else "6", inzone="External",
                          outzone="External", tag=("background-scan", "", "internet scanner", "T1595.001"))
            # I5: Log4Shell probes against the web server, prevented by IPS
            for _ in range(rng.randint(0, 4)):
                ts = d0 + timedelta(seconds=rng.randint(0, 86399))
                self.ips(ts, rng.choice(I5_PROBES), PUB_WEB, 443, "Prevent",
                         "Apache Log4j Remote Code Execution (CVE-2021-44228)",
                         "JNDI lookup in HTTP header", "CVE-2021-44228",
                         "https://track.lotusfreight.example/", xlatedst=WEB_DMZ, method="GET",
                         tag=("attack", "I5", "Log4Shell probe (prevented)", T["exploit-public"]))

    # -------------------------------------------------------------- attacks
    def i1_sweep(self):
        """One botnet node walks ~650 services of the gateway for 6.5 hours;
        implied rules accept the gateway's own services (the customer's Jun 2026 SOC case)."""
        rng, tag = self.rng, ("attack", "I1", "service sweep of the gateway", T["scan-ext"])
        start, end = datetime(2026, 7, 9, 13, 2, tzinfo=TZ), datetime(2026, 7, 9, 19, 47, tzinfo=TZ)
        span = int((end - start).total_seconds())
        ports = rng.sample(range(1, 65536), 640) + [443, 18264, 500, 4500, 80, 22, 3389, 445, 23, 8080]
        for _ in range(9300):
            ts = start + timedelta(seconds=rng.randint(0, span))
            self.conn(ts, I1_SWEEPER, PUB_GW, rng.choice(ports), "cleanup", inzone="External",
                      outzone="Local", tag=tag)
        acc = ("attack", "I1", "accepted by implied rule after the sweep", T["scan-ext"])
        for _ in range(330):
            ts = start + timedelta(seconds=rng.randint(600, span))
            port = rng.choices((443, 18264, 500), (5, 4, 1))[0]
            self.conn(ts, I1_SWEEPER, PUB_GW, port, "implied", proto="17" if port == 500 else "6",
                      inzone="External", outzone="Local", tag=acc)
        for _ in range(14):
            ts = start + timedelta(seconds=rng.randint(0, span))
            self.conn(ts, I1_SWEEPER, PUB_GW, rng.choice(ports), "cleanup", action="Reject",
                      inzone="External", outzone="Local", tag=tag)

    def i2_chain(self):
        rng = self.rng
        D = lambda m, d, h, mi, s=0: datetime(2026, m, d, h, mi, s, tzinfo=TZ)  # noqa: E731
        cve = "CVE-2024-24919"
        attack = "Check Point Security Gateway Information Disclosure (CVE-2024-24919)"
        # 2a - mass scanning for the vulnerable endpoint, IPS protection in Detect mode
        for src in I2_SCANNERS:
            t = D(7, 20, rng.randint(0, 20), rng.randint(0, 59))
            for _ in range(rng.randint(2, 5)):
                self.ips(t, src, PUB_GW, 443, "Detect", attack, "Path traversal in /clients/MyCRL", cve,
                         f"https://{PUB_GW}/clients/MyCRL",
                         tag=("attack", "I2", "2a mass scanning for CVE-2024-24919", T["exploit-public"]))
                t += timedelta(seconds=rng.randint(1, 30))
        # 2b - the targeted read: shadow file, then the gateway's own config
        t = D(7, 21, 2, 13, 4)
        for path in ("aCSHELL/../../../../../../../etc/shadow", "aCSHELL/../../../../../../../etc/passwd",
                     "aCSHELL/../../../../../../../home/admin/.bash_history",
                     "aCSHELL/../../../../../../../opt/CPsuite-R81.20/fw1/conf/fwauth.NDB"):
            self.ips(t, I2_ACTOR, PUB_GW, 443, "Detect", attack, f"Path traversal: {path}", cve,
                     f"https://{PUB_GW}/clients/MyCRL",
                     tag=("attack", "I2", "2b CVE-2024-24919 file read", T["exploit-public"]))
            t += timedelta(seconds=rng.randint(4, 40))
        # 2c - a stale local VPN account with password-only authentication
        t = D(7, 21, 2, 31, 12)
        for _ in range(3):
            self.vpn_login(t, I2_ACTOR, "vpn_test", False,
                           tag=("attack", "I2", "2c failed sign-in, local account vpn_test", T["valid-account"]))
            t += timedelta(seconds=rng.randint(15, 50))
        self.vpn_login(D(7, 21, 2, 34, 2), I2_ACTOR, "vpn_test", True, I2_VPN_IP,
                       tag=("attack", "I2", "2c VPN sign-in as vpn_test", T["ext-remote"]))
        # 2d - discovery of the server VLAN from the Office Mode address
        allowed = {(DC1, 445), (DC1, 389), (DC1, 88), (DC2, 445), (FS, 445), (RDS, 3389)}
        t = D(7, 21, 2, 40, 0)
        tag = ("attack", "I2", "2d discovery of the server VLAN", T["discovery"])
        for host in range(1, 255):
            for port in (445, 3389, 135, 5985, 22):
                t += timedelta(milliseconds=rng.randint(200, 1300))
                ip = f"192.168.20.{host}"
                ok = (ip, port) in allowed
                self.conn(t, I2_VPN_IP, ip, port, "ra" if ok else "cleanup", inzone="VPN", outzone="Servers",
                          tag=tag)
        # 2e - RDP to the terminal server; a tool fetched from the actor's server
        self.conn(D(7, 21, 3, 42, 10), I2_VPN_IP, RDS, 3389, "ra", inzone="VPN", outzone="Servers",
                  update=(7140, 18_000_000, 160_000_000),
                  tag=("attack", "I2", "2e RDP to the terminal server", T["rdp"]))
        self.conn(D(7, 21, 4, 5, 33), RDS, I2_ACTOR, 443, "srv_out", xlatesrc=PUB_GW, inzone="Servers",
                  update=(41, 52_000, 9_400_000),
                  tag=("attack", "I2", "2e tool download to the terminal server", T["tool-transfer"]))
        # 2f - re-entries with the same account; the third one installs the beacon
        for when, src in zip((D(8, 2, 1, 12), D(8, 11, 23, 40), D(8, 12, 13, 58), D(9, 25, 22, 30),
                              D(9, 26, 0, 40)), I2_REENTRY):
            self.vpn_login(when, src, "vpn_test", True, I2_VPN_IP,
                           tag=("attack", "I2", "2f re-entry as vpn_test", T["ext-remote"]))
            self.conn(when + timedelta(seconds=rng.randint(30, 90)), I2_VPN_IP, RDS, 3389, "ra",
                      inzone="VPN", outzone="Servers",
                      update=(rng.randint(1800, 5400), rng.randint(3_000_000, 9_000_000),
                              rng.randint(40_000_000, 120_000_000)),
                      tag=("attack", "I2", "2f RDP to the terminal server", T["rdp"]))
        # 2g - C2 beacon from the terminal server, sleep 300 s, jitter 15 %
        t, stop = D(8, 12, 14, 5, 17), D(9, 27, 6, 0)
        tag = ("attack", "I2", "2g C2 beacon", T["c2-web"])
        while t < stop:
            self.conn(t, RDS, I2_C2, 443, "srv_out", xlatesrc=PUB_GW, inzone="Servers",
                      domain="cdn.msupdate-check.example", tag=tag)
            # From Aug 30 the Anti-Bot signature knows it - in Detect mode, so nothing is blocked.
            if t >= D(8, 30, 9, 0) and rng.random() < 0.012:
                self.antibot(t, RDS, I2_C2, 443, "Detect", "CobaltStrike",
                             "Backdoor.Win32.CobaltStrike.TC.ab", "cdn.msupdate-check.example",
                             tag=("attack", "I2", "2g Anti-Bot detects the beacon (Detect mode)", T["c2-web"]))
            t += timedelta(seconds=round(300 * rng.uniform(0.85, 1.15)))
        # 2h - rclone-style exfiltration from the file server to MEGA, Saturday night
        t = D(9, 26, 1, 5, 40)
        for _ in range(18):
            secs = rng.randint(500, 1100)
            self.conn(t, FS, I2_EXFIL, 443, "srv_out", xlatesrc=PUB_GW, inzone="Servers",
                      domain="gfs208n103.userstorage.mega.co.nz",
                      update=(secs, rng.randint(300_000_000, 1_900_000_000), rng.randint(400_000, 2_000_000)),
                      extra={"user_agent": "rclone/v1.66.0"},
                      tag=("attack", "I2", "2h exfiltration to cloud storage", T["exfil-cloud"]))
            t += timedelta(seconds=secs + rng.randint(5, 60))
        # 2i - spread from the terminal server over SMB / RPC, then encryption
        t = D(9, 27, 2, 10, 0)
        tag = ("attack", "I2", "2i SMB spread from the terminal server", T["smb"])
        targets = [u["ip"] for u in self.users] + [DC1, DC2, FS, ERP]
        encrypted = []
        for ip in targets:
            for port in (445, 135):
                t += timedelta(milliseconds=rng.randint(300, 2500))
                ok = ip.startswith("192.168.10.") or ip.startswith("192.168.20.")
                self.conn(t, RDS, ip, port, "it_smb" if ok else "cleanup", inzone="Servers",
                          outzone="Servers" if ip.startswith("192.168.20.") else "Users", tag=tag)
            if ip.startswith("192.168.10.") or ip.startswith("192.168.20."):
                encrypted.append(ip)
        impact_start, back = D(9, 27, 2, 45), D(9, 29, 9, 0)
        for ip in encrypted:
            self.silent.setdefault(ip, []).append((impact_start, back))
        return encrypted

    def i3_spray(self):
        rng = self.rng
        names = ["admin", "administrator", "test", "vpn", "vpnuser", "user", "support", "backup",
                 "scanner", "guest", "info", "sales", "it", "helpdesk", "remote", "lotus", "lotusfreight",
                 "operator", "training", "temp"]
        names += [u["login"] for u in rng.sample(self.users, 25)]
        start = datetime(2026, 8, 4, 22, 0, tzinfo=TZ)
        span = 30 * 3600
        for src in I3_POOL:
            t = start + timedelta(seconds=rng.randint(0, span))
            for name in rng.sample(names, rng.randint(3, 11)):
                self.vpn_login(t, src, name, False,
                               tag=("attack", "I3", "password spray against the Remote Access VPN", T["spray"]))
                t += timedelta(seconds=rng.randint(20, 400))

    def i4_qakbot(self):
        rng = self.rng
        u = self.users[95]                       # a warehouse workstation, 192.168.11.x
        D = lambda h, mi, s=0: datetime(2026, 8, 18, h, mi, s, tzinfo=TZ)  # noqa: E731
        self.conn(D(9, 52, 31), u["ip"], I4_DROPPER, 80, "internet", product="URL Filtering", user=u,
                  xlatesrc=PUB_GW, domain="invoice-dhl-th.example",
                  extra={"resource": "http://invoice-dhl-th.example/doc/INV-0818-2026.zip", "method": "GET",
                         "app_category": "Uncategorized", "matched_category": "Uncategorized", "app_risk": "1"},
                  update=(3, 1_100, 486_000),
                  tag=("attack", "I4", "malicious link: zip from a look-alike domain", T["phish-link"]))
        t = D(9, 55, 10)
        tag = ("attack", "I4", "QakBot C2 on 443 / 995 / 2222", T["c2-port"])
        while t < D(11, 18):
            c2 = rng.choice(I4_C2)
            port = {I4_C2[0]: 443, I4_C2[1]: 995, I4_C2[2]: 2222}[c2]
            if c2 == I4_C2[2]:
                self.antibot(t, u["ip"], c2, port, "Prevent", "Qbot", "Trojan.Win32.Qbot.TC.c",
                             c2, user=u, tag=("attack", "I4", "Anti-Bot blocks QakBot C2", T["c2-port"]))
            else:
                self.conn(t, u["ip"], c2, port, "internet", user=u, xlatesrc=PUB_GW, tag=tag,
                          update=(rng.randint(2, 40), rng.randint(900, 60_000), rng.randint(1_500, 200_000)))
                if c2 == I4_C2[1] and rng.random() < 0.3:
                    self.antibot(t, u["ip"], c2, port, "Detect", "Qbot", "Trojan.Win32.Qbot.TC.a", c2, user=u,
                                 tag=("attack", "I4", "Anti-Bot detects QakBot C2", T["c2-port"]))
            t += timedelta(seconds=rng.randint(40, 420))
        t = D(10, 31, 0)
        tag = ("attack", "I4", "SMB sweep of the server and office VLANs", T["discovery"])
        for net in ("192.168.20", "192.168.10"):
            for host in range(1, 255):
                t += timedelta(milliseconds=rng.randint(150, 900))
                ip = f"{net}.{host}"
                self.conn(t, u["ip"], ip, 445, "servers" if ip == FS else "smb_vlan", user=u,
                          outzone="Servers" if net.endswith("20") else "Users", tag=tag)
        self.silent.setdefault(u["ip"], []).append((D(11, 20), datetime(2026, 8, 19, 10, 0, tzinfo=TZ)))

    def i5_callback(self):
        t = datetime(2026, 8, 27, 3, 14, 52, tzinfo=TZ)
        self.ips(t, I5_PROBES[3], PUB_WEB, 443, "Detect",
                 "Apache Log4j Remote Code Execution (CVE-2021-44228)",
                 "Obfuscated JNDI lookup in User-Agent (${${lower:j}ndi:...})", "CVE-2021-44228",
                 "https://track.lotusfreight.example/api/track", xlatedst=WEB_DMZ, method="GET",
                 tag=("attack", "I5", "obfuscated Log4Shell probe passes (Detect)", T["exploit-public"]))
        for i in range(3):
            self.conn(t + timedelta(seconds=2 + i * 3), WEB_DMZ, I5_CALLBACK, 1389, "dmz_out", inzone="DMZ",
                      tag=("attack", "I5", "LDAP callback from the web server, dropped", T["c2-port"]))

    def i6_ssh_brute(self):
        rng = self.rng
        t = datetime(2026, 9, 3, 14, 10, 7, tzinfo=TZ)
        tag = ("attack", "I6", "SSH brute force on the published SFTP server", T["brute"])
        while t < datetime(2026, 9, 3, 14, 55, tzinfo=TZ):
            self.conn(t, I6_BRUTE, PUB_SFTP, 22, "sftp", xlatedst=SFTP_DMZ, inzone="External", outzone="DMZ",
                      tag=tag)
            t += timedelta(milliseconds=rng.randint(500, 2400))

    # -------------------------------------------------------------- output
    def build(self):
        self.i4_qakbot()
        encrypted = self.i2_chain()   # sets the silent windows the background obeys
        self.background()
        self.i1_sweep()
        self.i3_spray()
        self.i5_callback()
        self.i6_ssh_brute()
        return encrypted


def esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def body(f: dict) -> str:
    head = sorted(k for k in f if k in HEAD_KEYS)
    rest = sorted(k for k in f if k not in HEAD_KEYS and k != "__policy_id_tag")
    keys = head + (["__policy_id_tag"] if "__policy_id_tag" in f else []) + rest
    return "11241 - [" + "; ".join(f'{k}:"{esc(f[k])}"' for k in keys) + "]"


ELA_HEADER = ('"#","Message","DisplayName","LogType","Device","Time","Severity","Facility","Source","Type",'
              '"Destination IP","Username","Source IP","Description","Event Name","Event ID","FORMATID",'
              '"Details","Host Type",')


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outdir")
    ap.add_argument("--seed", type=int, default=20260701)
    args = ap.parse_args()
    out = pathlib.Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)

    g = Gen(args.seed)
    g.build()
    # newest first, as EventLog Analyzer writes; ties keep a stable order
    events = sorted(enumerate(g.events), key=lambda x: (x[1][0], x[0]), reverse=True)
    files, truth = [], []
    for month in (7, 8, 9):
        name = f"lotus-checkpoint-2026-{month:02d}.csv"
        path = out / name
        n = 0
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("Search Results\n" + ELA_HEADER + "\n")
            for _, (ts, f, tag) in events:
                if ts.month != month:
                    continue
                n += 1
                local = ts.astimezone(TZ).strftime("%Y-%m-%d %H:%M:%S")
                user = f.get("src_user_name", "-").strip() or "-"
                msg = body(f).replace('"', '""')
                fh.write(f'"{n}","{msg}",-,CheckPoint Device,{ELA_DEVICE},{local},information,Local0,'
                         f'CheckPoint,-,-,{user},-,-,-,-,-,-,CheckPoint Device,\n')
                if tag:
                    label, inc, stage, tech = tag
                    truth.append((name, n, local, f["loguid"], label, inc, stage, tech))
        files.append((path, n))
    with open(out / "ground_truth.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "row", "time_gmt7", "loguid", "label", "incident", "stage", "technique"])
        w.writerows(sorted(truth, key=lambda r: (r[2], r[0], r[1])))
    zpath = out / "lotus-checkpoint-2026Q3.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for path, _ in files:
            z.write(path, path.name)
    for path, n in files:
        print(f"{path.name}: {n:,} rows, {path.stat().st_size / 1e6:.1f} MB")
    print(f"{zpath.name}: {zpath.stat().st_size / 1e6:.1f} MB; ground_truth.csv: {len(truth):,} rows")


if __name__ == "__main__":
    main()
