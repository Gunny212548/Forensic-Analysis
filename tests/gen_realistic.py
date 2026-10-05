"""Generate a week of realistic logs with one attack buried in ordinary traffic.

Unlike gen_usecase.py (45 rows, nearly all of them the attack), most of what
this writes is an ordinary office going about its week, so the rules have to
find the incident the way they would in a real export: in the noise, next to
benign activity some rules will also fire on.

    python tests/gen_realistic.py <outdir> [--seed N]

Writes, for the fictitious "Meridian Foods" (120 staff, 2026-06-01..07,
GMT+7):

  meridian-paloalto-traffic.csv  Palo Alto traffic export (the real 117-column
                                 header from the corpus), newest first
  meridian-esxi-auth.log         ESXi auth.log of host 10.40.1.50
  meridian-azure-signins.csv     Entra ID interactive sign-ins export, newest first
  meridian-logs.zip              the three above in one archive (= one case)
  ground_truth.csv               file, line, label, stage for every row that
                                 is not plain benign traffic

The incident (label "attack"), all on Wed 2026-06-03 unless noted:
  1. 02:00  password spray against ~40 Entra ID accounts from a proxy pool in
            203.0.113.0/24; pornthip.k fails from 6 sources...
  2. 02:41  ...then succeeds, and the session is reused from 4 more pool
            addresses within the hour
  3. 09:05  the stolen account signs in to the GlobalProtect VPN app
  4. 09:12  from VPN address 10.40.200.23: sweep of the server subnet, mostly
            refused, but 22/443 to ESXi and 445 to the file server are allowed
  5. 09:41  SSH brute force of root on ESXi 10.40.1.50 (invalid users first),
            success at 10:05, root password changed at 10:09; returns Jun 4
  6. 11:02  file server 10.40.1.20 starts beaconing to 198.51.100.77:443
            every ~10 min until the end of the export
  7. Jun 6 01:10  four large uploads from 10.40.1.20 to 198.51.100.77

Also labelled, because they are not the incident but are not plain benign
either: "background-scan" (internet scanners refused at the perimeter, some
of them sweeping enough ports to be flagged) and "benign-periodic" (a
monitoring agent polling a SaaS endpoint on a timer, which is exactly what a
beacon looks like - CLAUDE.md gotcha #15).

Everything is drawn from one seeded RNG, so the same seed reproduces the same
files byte for byte. Attacker infrastructure uses the RFC 5737 documentation
ranges so no real host is accused. Benign SaaS and internet addresses are
real-looking public addresses; with threat-intel feeds loaded, one of them can
occasionally match a feed (R3003-R3006), which is realistic but means intel
rule counts depend on the feed snapshot.

App risk/category values are taken from the corpus where the app appears
there and approximated otherwise.
"""
import argparse
import base64
import csv
import io
import ipaddress
import pathlib
import random
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

TZ = timezone(timedelta(hours=7))
START = datetime(2026, 6, 1, tzinfo=TZ)  # Monday
DAYS = 7

# ------------------------------------------------------------------ actors
FIRST = ["Somchai", "Suda", "Anan", "Pornthip", "Kittisak", "Nattaya", "Wichai", "Siriporn",
         "Prasert", "Kanya", "Thanakorn", "Waraporn", "Chaiwat", "Jiraporn", "Narong", "Ratana",
         "Surasak", "Duangjai", "Yuthana", "Supaporn", "Ekkachai", "Malee", "Pichit", "Orawan",
         "Teerapong", "Kulthida", "Apichat", "Sasithorn", "Boonmee", "Nittaya"]
LAST = ["Srisuk", "Wongsa", "Chaiyaporn", "Kaewmanee", "Thongdee", "Rattanakul", "Saetang",
        "Boonyarat", "Phromma", "Inthong", "Suwan", "Charoen"]

OFFICE_NAT = "192.0.2.10"       # staff egress, also Entra ID "office" address
WEB_PUBLIC = "192.0.2.20"       # DMZ web server as seen from the internet
DC, FILESRV, MONITOR, JUMP, ESXI = "10.40.1.10", "10.40.1.20", "10.40.1.30", "10.40.1.40", "10.40.1.50"
WEB_DMZ = "10.40.50.10"
ATTACK_VPN = "10.40.200.23"
C2 = "198.51.100.77"
SPRAY_POOL = [f"203.0.113.{n}" for n in (12, 19, 27, 33, 45, 51, 64, 78, 86, 91, 102, 117, 133, 149)]
POOL_CITY = ["Amsterdam, Noord-Holland, NL", "Frankfurt am Main, Hessen, DE", "Bucharest, Bucuresti, RO",
             "Singapore, Central Singapore, SG", "Ashburn, Virginia, US", "Hong Kong, Hong Kong, HK",
             "Warsaw, Mazowieckie, PL", "Sao Paulo, Sao Paulo, BR"]
VICTIM = 3  # index of pornthip.k in the user list
ADMIN = 2   # anan.c, IT admin, the only person who uses SSH on ESXi

# Public ranges the benign destinations are drawn from (Microsoft, Google,
# Cloudflare, Akamai, AWS) - looked-like-real, not a claim about any host.
SAAS_NETS = ["13.107.6.0/24", "13.107.42.0/24", "52.97.0.0/16", "40.99.0.0/16", "142.250.0.0/16",
             "172.217.0.0/16", "104.16.0.0/14", "23.32.0.0/14", "52.84.0.0/15"]
TH_ISP_NETS = ["171.96.0.0/13", "184.22.0.0/16", "49.228.0.0/14", "58.8.0.0/14", "110.164.0.0/15"]

# app -> (dport, proto, risk, category, subcategory, technology, characteristic)
APPS = {
    "ssl": (443, "tcp", 4, "networking", "encrypted-tunnel", "browser-based",
            "able-to-transfer-file,has-known-vulnerability,tunnel-other-application,prone-to-misuse,pervasive-use"),
    "web-browsing": (80, "tcp", 4, "general-internet", "internet-utility", "browser-based",
                     "able-to-transfer-file,has-known-vulnerability,tunnel-other-application,prone-to-misuse,pervasive-use"),
    "ms-office365-base": (443, "tcp", 1, "saas", "office-programs", "browser-based", "pervasive-use"),
    "ms-teams": (443, "tcp", 2, "collaboration", "voip-video", "client-server", "able-to-transfer-file,pervasive-use"),
    "outlook-web-online": (443, "tcp", 1, "saas", "email", "browser-based", "able-to-transfer-file,pervasive-use"),
    "ms-onedrive-base": (443, "tcp", 1, "saas", "file-sharing", "client-server", "able-to-transfer-file,pervasive-use"),
    "google-base": (443, "tcp", 4, "general-internet", "internet-utility", "browser-based", "pervasive-use"),
    "quic-base": (443, "udp", 1, "networking", "infrastructure", "network-protocol", ""),
    "dns-base": (53, "udp", 3, "networking", "infrastructure", "network-protocol", "tunnel-other-application,pervasive-use"),
    "kerberos": (88, "tcp", 3, "networking", "infrastructure", "client-server", "pervasive-use"),
    "ldap": (389, "tcp", 2, "networking", "infrastructure", "client-server", "pervasive-use"),
    "ms-ds-smbv3": (445, "tcp", 3, "business-systems", "storage-backup", "client-server",
                    "able-to-transfer-file,has-known-vulnerability,pervasive-use"),
    "ms-update": (80, "tcp", 4, "business-systems", "software-update", "client-server", "pervasive-use"),
    "ocsp": (80, "tcp", 2, "networking", "infrastructure", "network-protocol", "pervasive-use"),
    "windows-push-notifications": (443, "tcp", 1, "general-internet", "internet-utility", "client-server", "pervasive-use"),
    "ssh": (22, "tcp", 4, "networking", "encrypted-tunnel", "client-server",
            "used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use"),
    "not-applicable": (0, "tcp", 1, "unknown", "unknown", "unknown", ""),
    "incomplete": (0, "tcp", 1, "unknown", "unknown", "unknown", ""),
}
# share of a workstation's sessions, and where each goes
WORKSTATION_MIX = [
    ("ssl", 30, "saas"), ("web-browsing", 7, "saas"), ("ms-office365-base", 12, "saas"),
    ("ms-teams", 6, "saas"), ("outlook-web-online", 4, "saas"), ("ms-onedrive-base", 4, "saas"),
    ("google-base", 4, "saas"), ("quic-base", 3, "saas"), ("dns-base", 10, DC),
    ("kerberos", 4, DC), ("ldap", 3, DC), ("ms-ds-smbv3", 7, FILESRV), ("ms-update", 2, "saas"),
    ("ocsp", 2, "saas"), ("windows-push-notifications", 2, "saas"),
]
SCAN_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 902, 1433, 3306, 3389, 5900, 5985, 8080]
INTERNET_SCAN_PORTS = [22, 23, 80, 443, 445, 3389, 8080, 5900, 1433, 3306, 6379, 9200, 8443, 21, 25, 5060]

PA_HEADER = (
    "Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,"
    "Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,"
    "Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,"
    "Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,"
    "IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,,"
    "Sequence Number,Action Flags,Source Country,Destination Country,,Packets Sent,Packets Received,"
    "Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,"
    "Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,"
    "Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,"
    "SCTP Chunks Sent,SCTP Chunks Received,UUID for rule,HTTP/2 Connection,link_change_count,policy_id,"
    "link_switches,sdwan_cluster,sdwan_device_type,sdwan_cluster_type,sdwan_site,dynusergroup_name,"
    "XFF address,Source Device Category,Source Device Profile,Source Device Model,Source Device Vendor,"
    "Source Device OS Family,Source Device OS Version,Source Hostname,Source Mac Address,"
    "Destination Device Category,Destination Device Profile,Destination Device Model,"
    "Destination Device Vendor,Destination Device OS Family,Destination Device OS Version,"
    "Destination Hostname,Destination Mac Address,Container ID,POD Namespace,POD Name,"
    "Source External Dynamic List,Destination External Dynamic List,Host ID,Serial Number,"
    "Source Dynamic Address Group,Destination Dynamic Address Group,session_owner,High Res Timestamp,"
    "nssai_sst,nssai_sd,Subcategory of app,Category of app,Technology of app,Risk of app,"
    "Characteristic of app,Container of app,Tunneled app,SaaS of app,Sanctioned State of app,offloaded,"
    "flow_type,cluster_name,AI Traffic,AI Forward Error,K8S Cluster ID"
).split(",")

AZ_HEADER = (
    "Date (UTC),Request ID,User agent,Correlation ID,User ID,User,Username,User type,"
    "Cross tenant access type,Incoming token type,Authentication Protocol,Unique token identifier,"
    "Original transfer method,Client credential type,Token Protection - Sign In Session,"
    "Token Protection - Sign In Session StatusCode,Application,Application ID ,App owner tenant ID,Resource,"
    "Resource ID ,Resource tenant ID,Resource owner tenant ID,Home tenant ID,Home tenant name,IP address,"
    "Location,Status,Sign-in error code,Failure reason,Client app,Device ID,Browser,Operating System,"
    "Compliant,Managed,Join Type,Multifactor authentication result,Multifactor authentication auth method,"
    "Multifactor authentication auth detail,Authentication requirement,Sign-in identifier,Session ID,"
    "IP address (seen by resource),Through Global Secure Access,Global Secure Access IP address,"
    "Autonomous system  number,Flagged for review,Token issuer type,Incoming token type,Token issuer name,"
    "Latency,Conditional Access,Managed Identity type,Associated Resource Id,Federated Token Id,"
    "Federated Token Issuer"
).split(",")

MS_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
# (application, application id, resource, resource id)
AZ_APPS = [
    ("One Outlook Web", "9199bf20-a13f-4107-85dc-02114787ef48", "Office 365 Exchange Online",
     "00000002-0000-0ff1-ce00-000000000000"),
    ("OfficeHome", "4765445b-32c6-49b0-83e6-1d93765276ca", "OfficeHome", "4765445b-32c6-49b0-83e6-1d93765276ca"),
    ("Microsoft Teams", "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Graph",
     "00000003-0000-0000-c000-000000000000"),
    ("Microsoft Office", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "Office 365 SharePoint Online",
     "00000003-0000-0ff1-ce00-000000000000"),
]
UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/148.0.0.0 Safari/537.36")
UA_EDGE = UA_CHROME + " Edg/147.0.0.0"
UA_IOS = ("Mozilla/5.0 (iPhone; CPU iPhone OS 19_4 like Mac OS X) AppleWebKit/605.1.15 "
          "(KHTML, like Gecko) Version/19.4 Mobile/15E148 Safari/604.1")
FAIL_TEXT = {
    "50126": "Error validating credentials due to invalid username or password.",
    "50140": "This occurred due to 'Keep me signed in' interrupt when the user was signing in.",
    "50074": "Strong Authentication is required.",
}


class Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)
        self.session_id = 400000
        self.pa: list[tuple[datetime, list[str], str, str]] = []   # (ts, row, label, stage)
        self.auth: list[tuple[datetime, str, str, str]] = []
        self.az: list[tuple[datetime, list[str], str, str]] = []
        self.tenant = self.uuid()
        self.gp_app = self.uuid()
        self.users = self._users()
        self.saas = [self.ip_in(self.r.choice(SAAS_NETS)) for _ in range(80)]

    # ---------------------------------------------------------------- helpers
    def uuid(self) -> str:
        return str(uuid.UUID(int=self.r.getrandbits(128), version=4))

    def ip_in(self, net: str) -> str:
        n = ipaddress.ip_network(net)
        return str(n.network_address + self.r.randrange(1, n.num_addresses - 1))

    def public_ip(self) -> str:
        while True:
            ip = ipaddress.ip_address(self.r.getrandbits(32))
            if ip.is_global and not ip.is_multicast:
                return str(ip)

    def _users(self):
        users, seen = [], set()
        for i in range(120):
            while True:
                first, last = self.r.choice(FIRST), self.r.choice(LAST)
                if i == ADMIN:
                    first, last = "Anan", "Chaiyaporn"
                if i == VICTIM:
                    first, last = "Pornthip", "Kaewmanee"
                sam = f"{first.lower()}.{last[0].lower()}"
                if sam not in seen:
                    break
            seen.add(sam)
            users.append({
                "sam": sam, "name": f"{first} {last}", "upn": f"{sam}@meridian-foods.example",
                "id": self.uuid(), "ws": f"10.40.10.{11 + i}", "home": self.ip_in(self.r.choice(TH_ISP_NETS)),
                "device": self.uuid(), "edge": self.r.random() < 0.35,
            })
        return users

    def work_time(self, day: datetime) -> datetime:
        """A moment in office hours, denser mid-morning and mid-afternoon."""
        hour = self.r.choice([8, 9, 9, 10, 10, 10, 11, 11, 13, 13, 14, 14, 15, 15, 16, 16, 17])
        return day + timedelta(hours=hour, seconds=self.r.randrange(3600))

    # --------------------------------------------------------------- palo alto
    def pa_row(self, ts, src, dst, app, *, action="allow", dport=None, user="", szone="Trust",
               dzone="Untrust", rule="Users-to-Internet", sent=None, recv=None, elapsed=None,
               nat=True, label="benign", stage=""):
        port, proto, risk, cat, sub, tech, chars = APPS[app]
        dport = port if dport is None else dport
        self.session_id += self.r.randrange(1, 40)
        if action == "allow":
            elapsed = elapsed if elapsed is not None else int(self.r.lognormvariate(2.5, 1.3))
            sent = sent if sent is not None else int(self.r.lognormvariate(7.8, 1.2))
            recv = recv if recv is not None else int(self.r.lognormvariate(9.0, 1.6))
            end = "aged-out" if proto == "udp" else self.r.choice(["tcp-fin"] * 8 + ["tcp-rst-from-client"] * 2)
            subtype = "end"
        else:
            elapsed, sent, recv, end, subtype = 0, self.r.choice([66, 74, 78]), 0, "policy-deny", "deny"
        start = ts - timedelta(seconds=elapsed)
        pkts_s, pkts_r = max(1, sent // 900), (max(1, recv // 1300) if recv else 0)
        public = not ipaddress.ip_address(dst).is_private
        sport = self.r.randrange(49152, 65535)
        row = dict.fromkeys(PA_HEADER, "")
        row.update({
            "Domain": "1", "Receive Time": ts.strftime("%d/%m/%Y %H:%M"), "Serial #": "013201031882",
            "Type": "TRAFFIC", "Threat/Content Type": subtype, "Config Version": "2561",
            "Generate Time": ts.strftime("%d/%m/%Y %H:%M"), "Source address": src, "Destination address": dst,
            "NAT Source IP": OFFICE_NAT if (public and nat and action == "allow") else "",
            "Rule": rule, "Source User": f"meridian\\{user}" if user else "", "Application": app,
            "Virtual System": "vsys1", "Source Zone": szone, "Destination Zone": dzone,
            "Inbound Interface": {"Trust": "ethernet1/2", "Servers": "ethernet1/3", "Untrust": "ethernet1/1",
                                  "SSL-VPN": "tunnel.10"}[szone],
            "Outbound Interface": {"Untrust": "ethernet1/1", "Servers": "ethernet1/3", "DMZ": "ethernet1/4",
                                   "Trust": "ethernet1/2"}[dzone] if action == "allow" else "",
            "Log Action": "Log Forwarding ALL", "Time Logged": ts.strftime("%d/%m/%Y %H:%M"),
            "Session ID": str(self.session_id), "Repeat Count": "1", "Source Port": str(sport),
            "Destination Port": str(dport), "NAT Source Port": str(self.r.randrange(1024, 65535)) if public else "0",
            "NAT Destination Port": "0", "Flags": "0x400064" if public else "0x400000", "IP Protocol": proto,
            "Action": action, "Bytes": str(sent + recv), "Bytes Sent": str(sent), "Bytes Received": str(recv),
            "Packets": str(pkts_s + pkts_r), "Start Time": start.strftime("%d/%m/%Y %H:%M"),
            "Elapsed Time (sec)": str(elapsed), "Category": "any" if public else "private-ip-addresses",
            "Sequence Number": str(7524610000000000000 + self.session_id), "Action Flags": "0x0",
            "Source Country": "10.0.0.0-10.255.255.255" if src.startswith("10.") else "Unknown",
            "Destination Country": "10.0.0.0-10.255.255.255" if dst.startswith("10.") else "Unknown",
            "Packets Sent": str(pkts_s), "Packets Received": str(pkts_r), "Session End Reason": end,
            "DG Hierarchy Level 1": "0", "DG Hierarchy Level 2": "0", "DG Hierarchy Level 3": "0",
            "DG Hierarchy Level 4": "0", "Device Name": "MRD-PA-850", "Action Source": "from-policy",
            "Tunnel ID/IMSI": "0", "Parent Session ID": "0", "Tunnel": "N/A",
            "High Res Timestamp": ts.isoformat(timespec="milliseconds"),
            "Subcategory of app": sub, "Category of app": cat, "Technology of app": tech,
            "Risk of app": str(risk), "Characteristic of app": chars, "Tunneled app": app,
            "SaaS of app": "yes" if cat == "saas" else "no", "Sanctioned State of app": "no",
            "offloaded": "0", "flow_type": "NonProxyTraffic",
        })
        self.pa.append((ts, [row[h] if h else "" for h in PA_HEADER], label, stage))

    def benign_firewall(self):
        apps, weights = zip(*[((a, d), w) for a, w, d in WORKSTATION_MIX])
        for d in range(DAYS):
            day = START + timedelta(days=d)
            weekday = day.weekday() < 5
            for u in self.users:
                n = self.r.randrange(28, 44) if weekday else self.r.randrange(0, 4)
                for _ in range(n):
                    ts = self.work_time(day) if weekday else day + timedelta(seconds=self.r.randrange(86400))
                    app, dest = self.r.choices(apps, weights)[0] if weekday else \
                        self.r.choice([("ms-update", "saas"), ("windows-push-notifications", "saas"), ("ssl", "saas")])
                    if dest == "saas":
                        self.pa_row(ts, u["ws"], self.r.choice(self.saas), app, user=u["sam"])
                    else:
                        self.pa_row(ts, u["ws"], dest, app, user=u["sam"], dzone="Servers",
                                    rule="Users-to-Servers", nat=False)
                # the odd refused connection every office has
                if weekday and self.r.random() < 0.15:
                    self.pa_row(self.work_time(day), u["ws"], self.public_ip(), "not-applicable",
                                action="deny", dport=self.r.choice([135, 445, 3389, 8443]),
                                user=u["sam"], rule="interzone-default")
            # staff on the VPN in the evening
            if weekday:
                for u in self.r.sample(self.users[10:], 6):
                    vpn = f"10.40.200.{self.r.randrange(30, 90)}"
                    t0 = day + timedelta(hours=self.r.randrange(19, 22), minutes=self.r.randrange(60))
                    for k in range(self.r.randrange(4, 12)):
                        self.pa_row(t0 + timedelta(minutes=3 * k), vpn, FILESRV, "ms-ds-smbv3", user=u["sam"],
                                    szone="SSL-VPN", dzone="Servers", rule="VPN-to-Servers", nat=False)
            # servers: Windows Update, DC DNS forwarding
            for srv in (DC, FILESRV, MONITOR, JUMP):
                for _ in range(self.r.randrange(8, 20)):
                    self.pa_row(day + timedelta(seconds=self.r.randrange(86400)), srv,
                                self.r.choice(self.saas), self.r.choice(["ms-update", "ocsp", "dns-base"]),
                                szone="Servers", rule="Servers-to-Internet")
            # inbound to the public web server
            for _ in range(self.r.randrange(170, 230)):
                self.pa_row(day + timedelta(seconds=self.r.randrange(86400)), self.public_ip(), WEB_DMZ,
                            self.r.choice(["ssl", "ssl", "ssl", "web-browsing"]), szone="Untrust", dzone="DMZ",
                            rule="Inbound-Web-DMZ", nat=False)
        # IT admin managing ESXi over SSH from the jump host, weekdays
        for d in range(5):
            day = START + timedelta(days=d)
            for _ in range(self.r.randrange(1, 3)):
                self.pa_row(self.work_time(day), JUMP, ESXI, "ssh", user=self.users[ADMIN]["sam"],
                            szone="Servers", dzone="Servers", rule="Admin-to-Mgmt", nat=False,
                            elapsed=self.r.randrange(120, 1500))

    def periodic_monitor(self):
        """Monitoring agent polling its SaaS console every 15 min - periodic
        egress that is not C2 (gotcha #15: the rule localises, the analyst
        identifies)."""
        dst = self.saas[0]
        t = START + timedelta(seconds=self.r.randrange(900))
        while t < START + timedelta(days=DAYS):
            self.pa_row(t, MONITOR, dst, "ssl", szone="Servers", rule="Servers-to-Internet",
                        sent=self.r.randrange(1800, 2600), recv=self.r.randrange(4000, 6000), elapsed=1,
                        label="benign-periodic", stage="monitoring agent heartbeat")
            t += timedelta(seconds=900 + self.r.uniform(-20, 20))

    def internet_scanners(self):
        for i in range(90):
            src = self.public_ip()
            heavy = i < 3
            ports = self.r.sample(INTERNET_SCAN_PORTS, self.r.randrange(12, 16) if heavy else self.r.randrange(1, 6))
            t = START + timedelta(seconds=self.r.randrange(DAYS * 86400 - 3600))
            for p in ports:
                t += timedelta(seconds=self.r.randrange(1, 40))
                self.pa_row(t, src, WEB_PUBLIC, self.r.choice(["not-applicable", "incomplete"]), action="deny",
                            dport=p, szone="Untrust", dzone="DMZ", rule="interzone-default",
                            label="background-scan", stage="internet scanner")

    # ---------------------------------------------------------------- auth.log
    def auth_line(self, ts, msg, label="benign", stage=""):
        self.auth.append((ts, msg, label, stage))

    def esxi_session(self, ts, ip, user="root", fails=0, label="benign", stage="", pid=None):
        pid = pid or self.r.randrange(2100000, 2900000)
        port = self.r.randrange(49152, 65535)
        self.auth_line(ts, f"sshd[{pid}]: Connection from {ip} port {port}", label, stage)
        t = ts + timedelta(seconds=2)
        for _ in range(fails):
            t += timedelta(seconds=self.r.randrange(2, 6))
            self.auth_line(t, f"sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2", label, stage)
        sub = pid + self.r.randrange(3, 12)
        t += timedelta(seconds=self.r.randrange(2, 6))
        self.auth_line(t, f'sshd[{sub}]: pam_per_user: create_subrequest_handle(): doing map lookup for user "{user}"',
                       label, stage)
        self.auth_line(t, f'sshd[{sub}]: pam_per_user: create_subrequest_handle(): creating new subrequest handle',
                       label, stage)
        t += timedelta(seconds=1)
        self.auth_line(t, f"sshd[{pid}]: Accepted keyboard-interactive/pam for {user} from {ip} port {port} ssh2",
                       label, stage)
        self.auth_line(t, f"sshd[{sub}]: pam_unix(system-auth-generic:session): session opened for user {user} by (uid=0)",
                       label, stage)
        self.auth_line(t, f"sshd[{sub}]: Session opened for '{user}' on /dev/char/pty/t{self.r.randrange(0, 4)}",
                       label, stage)
        return t

    def benign_auth(self):
        admin_ip = JUMP
        for d in range(5):
            day = START + timedelta(days=d)
            for _ in range(self.r.randrange(1, 3)):
                ts = self.work_time(day)
                t = self.esxi_session(ts, admin_ip, fails=1 if self.r.random() < 0.15 else 0)
                for cmd in self.r.sample(["esxcli system version get", "esxcli network ip interface list",
                                          "esxcli storage core device list", "esxcli hardware memory get"], 2):
                    t += timedelta(seconds=self.r.randrange(10, 90))
                    self.auth_line(t, f"sshd[{self.r.randrange(2100000, 2900000)}]: User 'root' running command '{cmd}'")
                t += timedelta(seconds=self.r.randrange(60, 900))
                self.auth_line(t, f"sshd[{self.r.randrange(2100000, 2900000)}]: Session closed for 'root' on /dev/char/pty/t0")
        # vCenter rotates its vpxuser password
        self.auth_line(START + timedelta(days=4, hours=3, minutes=12, seconds=7),
                       "passwd: pam_unix(passwd:chauthtok): password changed for vpxuser",
                       "benign", "vCenter vpxuser rotation")
        # port check from the monitoring host every 10 minutes
        t = START + timedelta(seconds=self.r.randrange(600))
        while t < START + timedelta(days=DAYS):
            pid = self.r.randrange(2100000, 2900000)
            self.auth_line(t, f"sshd[{pid}]: Connection from {MONITOR} port {self.r.randrange(49152, 65535)}")
            self.auth_line(t, f"sshd[{pid}]: Did not receive identification string from {MONITOR}")
            t += timedelta(seconds=600 + self.r.uniform(-3, 3))

    # ------------------------------------------------------------------- azure
    def az_row(self, ts, u, ip, *, status="Success", code="", app=None, location="Bangkok, Krung Thep, TH",
               ua=None, client="Browser", managed=True, asn="7470", label="benign", stage=""):
        appname, appid, res, resid = app or self.r.choice(AZ_APPS)
        ua = ua or (UA_EDGE if u["edge"] else UA_CHROME)
        browser = "Edge 147.0.0" if "Edg/" in ua else ("Mobile Safari 19.4" if "iPhone" in ua else
                                                         ("Chrome 148.0.0" if "Chrome" in ua else ""))
        os_ = "Ios" if "iPhone" in ua else ("Windows10" if "Windows" in ua else "")
        tok = base64.urlsafe_b64encode(self.r.getrandbits(128).to_bytes(16, "big")).decode().rstrip("=")
        row = {h: "" for h in AZ_HEADER}
        row.update({
            "Date (UTC)":