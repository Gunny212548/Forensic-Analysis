"""Palo Alto Networks rules (specs/per_product_rules.md story 2, D11-D16).

Written on the PAN-OS Traffic log as the customer's exports carry it (fields:
PAN-OS 11.0 Traffic Log Fields, read 2026-10-22). The scanning, beaconing and
feed-match rules are the firewall rules every firewall shares
(rules_firewall.py) on Palo Alto rows; the URL category rule is Palo Alto's own.
The Authentication and Brute force areas are not applicable: a Traffic log
records sessions, not sign-ins (Q61).

A refusal is PAN-OS Action deny / drop / drop ICMP / reset both / client /
server (`verdict IN DENY_VERDICTS`); a destination service is its port.
"""

from . import rules_firewall

PRODUCT = "paloalto"
_SHARED = rules_firewall.build(PRODUCT, "PAN", service="dstport", unit="ports")

# PAN-DB categories its documentation defines as malicious content or C2
# ("URL Categories", Advanced URL Filtering, updated 2026-09-02). Grayware is
# left out: "does not pose a direct security threat". Phishing carries no
# technique until T1566 is read.
MALICIOUS_CATEGORIES = ("malware", "command-and-control", "ransomware", "compromised-website",
                        "phishing")

RULES: list[tuple[str, str]] = _SHARED["RULES"] + [
    # M5 the firewall's own verdict on the destination: a PAN-DB category it
    # defines as malicious (T1071.001 for malware / C2; phishing untagged).
    ("PAN-MAL-2", f"""
        INSERT INTO findings
        SELECT row_id, 'PAN-MAL-2', NULL,
               'PAN-DB category ''' || lower(category) || ''' (' ||
               coalesce(srcip, '?') || ' -> ' || coalesce(dstip, '?') || ')',
               CASE WHEN lower(category) = 'phishing' THEN []::VARCHAR[] ELSE ['T1071.001'] END
        FROM product_events
        WHERE lower(category) IN {MALICIOUS_CATEGORIES}
    """),
]
FROM_GENERIC = _SHARED["FROM_GENERIC"]
PREPARE = _SHARED["PREPARE"]
LEVEL = {**_SHARED["LEVEL"], "PAN-MAL-2": "high"}
LABELS = {**_SHARED["LABELS"], "PAN-MAL-2": "malicious URL category"}
FAMILY = {**_SHARED["FAMILY"], "PAN-MAL-2": "R3"}
