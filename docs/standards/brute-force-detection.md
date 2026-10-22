# Brute force: which behaviours a detection needs (sources read 2026-10-22)

The user's question (2026-10-22): what theory says a failed sign-in is part of a brute force,
and which behaviours a rule must look for. Every line below cites a document marked read in
`SOURCES.md`; nothing is from memory. Used by `specs/per_product_rules.md` (D14).

## The attacks being told apart

| Attack | What it is | Source |
|---|---|---|
| Password guessing (brute force proper) | many passwords against **one** account | ATT&CK T1110.001; CISA TA18-086A ("a single account by guessing the password") |
| Password spraying | **one** (or a few common) passwords against **many** accounts, slowly, to stay under lockout | ATT&CK T1110.003; CISA TA18-086A ("low-and-slow") |
| Credential stuffing | stolen username / password **pairs** tried at volume, no guessing | OWASP OAT-008 (ATT&CK T1110.004 not read - fetch blocked) |
| Credential cracking (umbrella) | trying values for usernames and/or passwords; includes spraying and username enumeration | OWASP OAT-007 |

## The behaviours (what a rule must measure)

| # | Behaviour | Why it marks an attack | Source |
|---|---|---|---|
| 1 | **Failed sign-in events**, including attempts on accounts that do not exist | the raw material; failures "for valid or invalid users" | ATT&CK AN1276; OWASP OAT-007 (username enumeration) |
| 2 | **Volume per account in a window** - a series of failures on the same or similar account | guessing needs many tries on one account | AN1521, AN1523; MS playbook "bad passwords in an hour and ... in a day" |
| 3 | **Spread from one source across many accounts in a window** | the spray signature | AN1336, AN1339; CISA "against multiple user accounts ... originating from a single IP address" |
| 4 | **Spread to one account from several sources** | distributed guessing hides each source | AN1521 ("from one or more remote IPs") |
| 5 | **Failure, then success** from the same source or for the same user | the guess worked; also success with failed MFA, or sign-in and sign-out in the same second | AN1275, AN1276, AN1522, AN1524; MS playbook |
| 6 | **Rate and regularity** - rapid succession, or a machine-regular interval | automation | CISA "thousands of logons, in rapid succession"; MS "a more regular time interval between attempts" |
| 7 | **Repeated attributes** - the same user agent, application, IP block | one tool behind many attempts | CISA "a common User Agent String"; MS "repetitive attributes (UA, target AppID, IP block/location)" |
| 8 | **Order of targets** - accounts tried in directory (alphabetical) order | a list being walked | MS "Failures in GAL order" |
| 9 | **Duration** | campaigns last | CISA "run for over two hours" |
| 10 | **Unusual origin for the account** - a location inconsistent with the user's normal | needs the account's own baseline | CISA indicators; MS Risky IP |

## The number

No standard read gives a detection threshold; one peer-reviewed measurement does (Javed &
Paxson, below: 20 failures to one server in an hour with no success, measured on one site). ATT&CK's analytics say "series", "many", "a
defined time window", "short window". What is published:
- NIST SP 800-63B-4 §3.2.2: a verifier disables an authenticator after **at most 100**
  consecutive failures - an upper bound for the system, not a detection threshold.
- CISA: lockout policies "allow three to five bad attempts during a set period of time" - which
  is exactly what spraying stays under.
- ATT&CK procedure examples: APT28 over 300 attempts per hour per account (guessing), about four
  per hour (spraying); Quad7 one attempt per 24 h, to evade thresholds.

So a fixed count in a fixed window catches the fast attack and misses the slow one by design.
Behaviours 6-10 and a window long enough for the slow case are what the sources offer instead;
choosing the numbers is Q62 of `specs/per_product_rules.md`.

## Javed & Paxson 2013 (CCS) - stealthy, distributed SSH brute forcing

Read 2026-10-22 (§1, §3.1, §4, §5 opening; `files/Javed-Paxson-2013-Distributed-SSH-Brute-Forcing.pdf`).
Eight years of SSH logs at LBNL (2005-2012, ~4,000 people). Peer-reviewed (ACM CCS 2013).

- **The one published, measured point-wise threshold found so far** (§3.1): legitimate users'
  failed attempts before an eventual success were measured; "instances exceeding 10 failed
  attempts are quite rare", so 20 was taken as conservative - a client with **20 or more failures
  to a single server, no success, within one hour** is a high-rate brute-forcer. The number is
  LBNL's; **the method** (measure how many failures the evidence's own legitimate users make
  before succeeding, then set the line above that tail) can be repeated on each case's evidence.
- **Why a per-source threshold is not enough** (§1, §4): a distributed attack spreads attempts
  over many sources so none crosses it. The paper watches the **site-wide failure count per n
  attempts** and flags a sustained rise with CUSUM change-point detection, then decides which
  sources took part. The attacks it found lasted up to about 1.5 months and "would have been
  completely missed by a point-wise host-based detector" - a 6-12 month export needs this view.
- **Telling a legitimate user from a brute-forcer** (§4.2, Fig. 4): a source/user pair that has
  **succeeded before** is a forgotten or mistyped password; failures on usernames **one edit
  away** from a username that succeeded (john / mjohn / johnm) are a forgotten username;
  legitimate users "have past history of successful logins".
- **Coordination glue** (§4.2) - what ties attack sources together: the same set of target
  servers or the same set of usernames, similar attempt counts per source, timing patterns, and
  "an alphabetical progression of usernames" (as Microsoft's "GAL order").

## What each product's log can show

| Behaviour needs | Palo Alto Traffic log (customer files) | Palo Alto GlobalProtect / Authentication log | Check Point Log Exporter (customer file) |
|---|---|---|---|
| a sign-in event with its outcome | **no** - sessions only | yes (format seen in Elastic's sample logs; field meanings to read from PAN-OS docs) | Web UI only: one `Failed Log In`, one `Log Out` |
| source address, account | source address; `Source User` on 1,329 rows | to confirm in PAN-OS field list | yes, on those records |
| user agent / application | no | GlobalProtect: client OS / version | to confirm |

Until a product's log shows behaviour 1, its Authentication and Brute force cells are
"not applicable", with this table as the reason.
