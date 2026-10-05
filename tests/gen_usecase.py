"""Generate a synthetic attack scenario with known ground truth.

Scenario "Nightfall" - 2026-02-14/15:
  1. 10.20.30.40 port-scans 10.10.1.5 (15 distinct ports, all denied)
  2. same host brute-forces SSH root on 10.10.1.5 (8 failures)
  3. tries 3 invalid usernames
  4. finally logs in successfully as root
  5. service account password changed afterwards
  6. 10.10.1.5 then talks out to 203.0.113.77 over high-risk SSL,
     including two >50MB transfers and one malware-flagged session

Benign noise is mixed in so the rules have something to NOT fire on.
"""
import csv
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)

VICTIM = "10.10.1.5"
ATTACKER = "10.20.30.40"
BENIGN = "10.10.1.9"
EXFIL_DST = "203.0.113.77"

# ---------------------------------------------------------------- auth.log
auth = []
# benign background: 3 connections + 2 successful logins
for i, t in enumerate(["09:02:11", "09:02:14", "11:40:02"]):
    auth.append(f"2026-02-14T{t}Z sshd[90{i}]: Connection from {BENIGN} port 4{i}001")
auth.append(f"2026-02-14T09:02:16Z sshd[900]: Accepted password for opsadmin from {BENIGN} port 40001")
auth.append(f"2026-02-14T11:40:05Z sshd[902]: Accepted password for opsadmin from {BENIGN} port 42001")

# stage 2: brute force - 8 failed root logins
for i in range(8):
    sec = 3 + i * 4
    auth.append(
        f"2026-02-14T22:10:{sec:02d}Z sshd[10{i:02d}]: "
        f"Failed password for root from {ATTACKER} port 51{i:03d} ssh2"
    )
# stage 3: 3 invalid usernames
for i, user in enumerate(["admin", "oracle", "backup"]):
    auth.append(f"2026-02-14T22:11:{30 + i * 3:02d}Z sshd[10{20 + i}]: Invalid user {user} from {ATTACKER}")
# stage 4: successful root login
auth.append(f"2026-02-14T22:12:00Z sshd[1030]: Connection from {ATTACKER} port 51099")
auth.append(f"2026-02-14T22:12:02Z sshd[1030]: Accepted password for root from {ATTACKER} port 51099 ssh2")
# stage 5: service account password changed
auth.append("2026-02-14T22:15:11Z passwd: pam_unix(passwd:chauthtok): password changed for svc_backup")

(out / "nightfall-auth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")

# ------------------------------------------------------------ firewall.csv
HEADER = [
    "Domain", "Receive Time", "Type", "Threat/Content Type", "Source address",
    "Destination address", "Application", "Action", "Log Action",
    "Destination Port", "Bytes Sent", "Bytes Received", "Risk of app",
    "Category of app", "High Res Timestamp",
]

rows = []


def row(ts, src, dst, app, action, dport, sent, risk, threat="end", cat="networking"):
    return {
        "Domain": "1", "Receive Time": "14/02/2026 22:09", "Type": "TRAFFIC",
        "Threat/Content Type": threat, "Source address": src,
        "Destination address": dst, "Application": app, "Action": action,
        "Log Action": "Log Forwarding ALL", "Destination Port": str(dport),
        "Bytes Sent": str(sent), "Bytes Received": "512", "Risk of app": str(risk),
        "Category of app": cat, "High Res Timestamp": ts,
    }


# stage 1: port scan - 15 distinct destination ports, all denied
SCAN_PORTS = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080]
for i, port in enumerate(SCAN_PORTS):
    rows.append(row(f"2026-02-14T22:{i:02d}:{(i * 3) % 60:02d}.100+07:00",
                    ATTACKER, VICTIM, "unknown-tcp", "deny", port, 64, 1))

# stage 6a: high-risk app allowed outbound (3 sessions)
for i in range(3):
    rows.append(row(f"2026-02-14T23:{10 + i:02d}:05.200+07:00",
                    VICTIM, EXFIL_DST, "ssl", "allow", 443, 4096, 5))

# stage 6b: two large outbound transfers (>50MB)
rows.append(row("2026-02-15T01:05:10.300+07:00", VICTIM, EXFIL_DST, "ssl", "allow", 443, 128_000_000, 5))
rows.append(row("2026-02-15T01:41:52.400+07:00", VICTIM, EXFIL_DST, "ssl", "allow", 443, 96_000_000, 5))

# stage 6c: one session flagged as malware
rows.append(row("2026-02-15T02:02:02.500+07:00", VICTIM, EXFIL_DST, "ssl", "allow", 443,
                8192, 5, threat="malware", cat="malware-c2"))

# benign noise: internal web browsing, low risk, allowed
for i in range(5):
    rows.append(row(f"2026-02-14T10:{i:02d}:00.000+07:00",
                    BENIGN, VICTIM, "web-browsing", "allow", 80, 2048, 2))

with open(out / "nightfall-firewall.csv", "w", encoding="utf-8", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=HEADER)
    w.writeheader()
    w.writerows(rows)

print(f"auth.log lines : {len(auth)}")
print(f"firewall rows  : {len(rows)}")
