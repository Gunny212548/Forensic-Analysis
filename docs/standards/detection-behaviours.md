# The other five areas: which behaviours a detection needs (sources read 2026-10-22)

The companion of `brute-force-detection.md`, for the remaining areas of D12
(`specs/per_product_rules.md`): Authentication, Scanning & policy, Malware & C2, Data transfer,
Threat intelligence. Every line cites a document marked read in `SOURCES.md`; nothing is from
memory. ATT&CK pages are content v20.0; their detection strategies (DET / AN ids) are all v1.0,
last modified 12 May 2026.

**How ATT&CK gives numbers.** No analytic's description holds a number. Some analytics list
*mutable elements* - the tuning knobs - and a few of those carry an example value ("e.g."). An
example value is the source's illustration, not a threshold it sets; a rule that uses one says so.

## Authentication (beyond brute force)

| # | Behaviour | Why it marks an attack | Source |
|---|---|---|---|
| A1 | Failures, then a success, then follow-on activity (lateral movement, file transfer) | the chain of a remote service broken into | T1133 DET0354 AN1004 (Windows, VPN gateway logs; examples ">5" failures, "15m"), AN1005 (Linux SSH / VPN) |
| A2 | Success from an uncommon location, or outside business hours | a valid account used by someone else | T1078 DET0560 AN1543 (example "9AM-6PM local"); T1133 AN1004 |
| A3 | One account signing in to many systems in a window | an account being used to move | T1078 AN1543 / AN1544 (`HostDensityThreshold`, no value) |
| A4 | Two distant locations in a short time ("impossible travel"); repeated MFA failures | credential theft on an identity provider | T1078 AN1546 (no values) |
| A5 | Remote-interactive sign-in by a sensitive or service account | accounts that should not log on that way | T1078 AN1543 (Type 10), AN1545 |

A2-A4 need the account's own history (its usual hours, places, systems): measured inside the
evidence, as Javed & Paxson measured legitimate users (`brute-force-detection.md`).

## Scanning & policy

| # | Behaviour | Why it marks an attack | Source |
|---|---|---|---|
| S1 | **Vertical scan** - one source, many destination ports on a host, in a window | service discovery | T1046 DET0376 AN1057 ("unique destination IPs or ports accessed within a time window", example "60 seconds"), AN1058 ("ports targeted per host within a short period") |
| S2 | **Horizontal scan / host sweep** - one source, many destination addresses | probing "multiple IP addresses across a network" | T1595.001 DET0817 AN1949; T1046 AN1057 (unique destination IPs) |
| S3 | **Repeated connection attempts**, uncommon flows | the external view of reconnaissance | T1595 DET0830 AN1962; AN1949 |
| S4 | Traffic that does not follow the protocol's standard | vulnerability scanning | T1595.002 DET0867 AN1999 |
| S5 | **Allowed after being denied** - the same source refused, then let through | a gap in the policy found by probing | no ATT&CK analytic names it; the SOC benchmark's implied-rule bypass (`CLAUDE.md`, *Real-world benchmark*) and R2004's measurement - internal method, stated as one |

The one vendor default found: PAN-OS 11.1 Zone Protection *Reconnaissance Protection* (page
updated 25 Jun 2026) - TCP / UDP port scan and IP protocol scan **interval 2 s**, host sweep
**interval 10 s**, **threshold 100 events** in the interval, default action Alert. These are the
firewall's own live defences - fast scans, seconds long. The page does not define a scan beyond
"protection against TCP port scans", nor say what log entry it writes. A slow scan over hours is
under them by construction, as a slow spray is under a lockout. Check Point's IPS Port Scan
protection: not obtained (support pages not searchable by the fetcher).

### Jung, Paxson, Berger & Balakrishnan 2004 (IEEE S&P) - Threshold Random Walk

Read 2026-10-22 (`files/Jung-2004-Fast-Portscan-Detection.pdf`; §1-4.2, 4.5, 5.1, 6, 7). TCP
connection logs of two sites (LBL ~6,000 hosts, ICSI ~200), 24-hour traces, scanners flagged by
the Bro NIDS as partial ground truth.
- **Counting in a window is the old method, and its weakness is named** (§2): NSM flagged a source
  reaching "more than 15 distinct destination IP addresses within a given time window"; Snort,
  more than X ports or Y addresses within Z seconds; Bro, N distinct addresses (default 100, the
  two sites used 20). Once the window is known an attacker scans more slowly; crawlers and
  proxies are flagged wrongly.
- **What separates a scanner is the failure ratio, not the count** (§3.1): a scanner does not
  know which hosts and services exist, so most of its attempts fail. About 99.5% of LBL's known
  bad sources hit only inactive hosts; the other sources split sharply into 0% or 100% failed.
  Under 80% failed was taken as benign ("somewhat arbitrary ... any value greater than 50% has
  little effect").
- **TRW** (§4): for each source, each first attempt to a *new* destination host is a success or
  a failure; a sequential likelihood-ratio test (Wald) decides scanner / benign / pending. With
  success probabilities 0.8 benign and 0.2 scanner, and bounds of 0.01 false alarms and 0.99
  detection, it decided after **4 or 5 distinct hosts** (Table 3), much sooner than Bro (~21-37)
  or Snort (~14). The parameters come from bounds the analyst chooses, not from counting events
  in a window, and the paper says they did not need re-tuning between its two sites.
- **Limits it states** (§1, §4.5, §6): one source address at a time - distributed scans are not
  covered; scans across many local addresses, **not vertical scans of one host**; an attacker
  can mix in connections to known-good servers to pull the walk towards benign.

**For a firewall log** the paper's "failure" is an attempt to an inactive host or service. A
firewall deny is a refusal by policy - not the same thing, though LBL's monitor sat outside the
firewall and the paper notes its known-bad sources hit nothing but inactive hosts largely
"due to the firewall". Reading Palo Alto `drop` / `deny` and Check Point `Drop` / `Reject` as
failures is therefore an adaptation and must be stated as one; the Session End Reason (Palo) /
the action value says which kind of failure it was.

## Malware & C2

| # | Behaviour | Why it marks an attack | Source |
|---|---|---|---|
| M1 | **Beaconing** - outbound callbacks at regular intervals | an implant checking in | T1071 DET0444 AN1226 ("beacon-like intervals"); T1071.001 DET0027 AN0076 (example "60±5s jitter") |
| M2 | **Asymmetric volume** - far more sent than received | C2 / upload over a web protocol | T1071 AN1225 (example ">90% outbound"); AN1227 ("High outbound/inbound ratio indicating C2 beacon"); T1071.001 AN0075 (example "outbound > inbound volume by 90%+") |
| M3 | **Protocol and port that do not belong together** - HTTPS on 8443, TLS on 8080 or 53 | hiding C2 on a port | T1571 DET0227 AN0633 (examples "allow 443/80/22 but flag 8088/587/3389"); T1573 DET0273 AN0763; T1071 AN1226 (example 8443, 5353) |
| M4 | Encrypted sessions to rare external hosts | C2 over TLS | T1573 AN0761, AN0762 |
| M5 | The firewall's own verdict - malware / C2 URL category, or a threat-prevention detection | the product classified it | the product's documentation (PAN-DB categories, Check Point blades) - to be read per product |

R2007's measured method (jitter = stddev / mean < 0.6 over >= 30 intervals, public egress only,
`rule_meta.py`) is M1 with a number calibrated on the customer's compromised host; DET0027's
"60±5s" is a single example, far tighter.

## Data transfer

| # | Behaviour | Why it marks an attack | Source |
|---|---|---|---|
| D1 | **Volume** to an external destination, per connection or over a short time | exfiltration | T1048 DET0131 AN0367 ("uncommonly high volume", example ">50MB in a single connection"); T1041 DET0348 AN0988 (example ">1MB in <5min") |
| D2 | **Sent > received** | data leaving, not arriving | T1041 AN0989 ("bytes_out > bytes_in"); T1567 DET0548 AN1511 ("high outbound-to-inbound data ratios") |
| D3 | **Off-hour** transfers | outside the owner's normal | T1048 AN0367 ("off-hour activity", "flag after-hours file transfer") |
| D4 | **Fixed-size chunks at a steady interval** | split to stay under size alerts | T1030 DET0213 AN0596 (examples "512B or 1024B"), AN0597 ("±5% size delta") |
| D5 | **The same destination at the same time each day** | scheduled exfiltration | T1029 DET0399 AN1118 ("same hour daily"), AN1119 ("24h for daily jobs"), AN1120 ("~24h ± 5m") |
| D6 | Uploads to a legitimate web service (Dropbox, Google Drive, OneDrive) | exfiltration hidden in ordinary traffic | T1567 AN1511 |

D4 and D5 are what a single-session threshold (R3001's 50 MB) cannot see; D5 needs days of
evidence - which a 6-12 month export has (D15).

## Threat intelligence

Here the behaviour is not a pattern but a **match**: an address, domain or URL in the evidence
that a feed names. NIST SP 800-150 (Oct 2016, §2.1 and §4.3-4.4) is the basis:
- An indicator is a technical artifact that "suggest[s] an attack is imminent or is currently
  underway or that a compromise may have already occurred" - e.g. the IP address of a suspected
  C2 server (§2.1). So a match is evidence, not a verdict: "a lone indicator may be ambiguous"
  until aggregated with other information (§4.3).
- Using indicators "as search keys" over security logs "to identify systems that may have already
  been compromised" is one of the uses it lists (§4.3) - exactly what a forensic case does.
- Trust in the source decides use: an untrusted source "may require independent validation"
  (§4.3). Each feed's name and trust therefore travels with the finding.
- A knowledgebase records, per indicator, its **source**, the **date it was collected** and the
  **"Length of time that an indicator is still considered valid"** (§4.4).

| # | Behaviour | Source |
|---|---|---|
| T1 | Traffic **to** an indicator address, allowed (the internal host reached it) | SP 800-150 §2.1 (C2 server address); T1071 |
| T2 | Traffic **from** an indicator address, allowed (it got in) | SP 800-150 §2.1 |
| T3 | Either, but blocked - the defence worked; context, lower weight | SP 800-150 §4.3 (block or alert on matches) |
| T4 | The match is **inside the indicator's validity window** | SP 800-150 §4.4 |

T4 matters with 6-12 month logs (D15): an address that is in today's feed may not have been
malicious when the event happened months ago, and addresses get reassigned. Today's rules
R3003-R3006 join every event against the current feed with no date (gotcha #17), so a feed
refresh moves old cases. A rule should carry the feed's date and the indicator's first-seen /
valid-until when the feed gives them, and say "matched a feed dated X" rather than "malicious".

## What a firewall log can show

| Behaviour needs | Palo Alto Traffic (customer files) | Check Point Log Exporter (customer file) |
|---|---|---|
| destination port, address, action | yes | service name instead of port (gotcha #8); address, action yes |
| bytes sent and received separately | yes (`Bytes Sent`, `Bytes Received`) | sk144192 documents bytes sent from / received by the client; `client_outbound_bytes` and `server_outbound_bytes` appear on about 2,689 records (field-to-meaning pairing to confirm) |
| session start / end time | yes | record time |
| account | `Source User` on 1,329 rows | on few records |
| process on the host | **no** - a firewall sees no process | no |

So every analytic keyed on a process (most of AN1057, AN0988, AN0759 ...) is out of a firewall's
reach; what it keeps is the network half - counts of ports and hosts, intervals, byte ratios,
time of day, port/protocol pairs.
