"""Check Point rules (specs/per_product_rules.md story 3, D11-D16).

Both Check Point readers feed these: Log Exporter records (checkpoint_le.py -
`service` is the destination port, sk144192) and SmartConsole exports (no port
column; `Service` is a name, read into `app` - gotcha #8). So a destination
service is `coalesce(dstport, app)`: the port where the log has one, the
service name where it does not. A refusal is Drop / Reject / Block / Prevent
(`verdict IN DENY_VERDICTS`); an allowed connection is Accept.

Check Point's Detect is no refusal and no acceptance - on the customer's
export all 61 are HTTPS inspection noting a certificate (OCSP unreachable, an
expired certificate), not a threat - so no rule here reads Detect as one.

Not written, and why (the case shows "no rule yet"):
- Authentication / Brute force: sk144192 documents `auth_status` but not its
  values, and the Identity Awareness pages could not be fetched; the export
  holds one Identity Awareness "Failed Log In" (a machine identity, no user).
- Malware & C2 by Check Point's URL category: no Check Point category
  definitions were obtainable.

CP-MAL-2 reads the Threat Prevention blades' own verdict (story 3b, the user's
test of 2026-10-22): sk144192 documents `product` ("Blade"), the Security
Gateway sections IPS / Anti-Bot / Anti-Virus / Threat Emulation, their action
(Prevent / Detect), `protection_name`, `malware_action` ("Communication with
C&C"), ThreatCloud `severity` and `confidence_level`. Those fields have no
canonical column, so the rule reads them from the Log Exporter record kept in
`raw` (checkpoint_le.py); a SmartConsole export's Blade column is not read yet.
A Prevent is a refusal, so its level is capped at medium like any refused row
(rules.apply_rules); a Detect let the connection through and stays high.
"""

from . import rules_firewall
from .rules import NON_PUBLIC_IPV4_RE

PRODUCT = "checkpoint"
_SHARED = rules_firewall.build(PRODUCT, "CP", service="coalesce(dstport, app)", unit="services")

# The Threat Prevention blades - sk144192's "Security Gateway - <blade> Fields".
THREAT_BLADES = ("IPS", "Anti-Bot", "Anti-Virus", "Threat Emulation")


def _field(name: str) -> str:
    """One Log Exporter field of the record kept in `raw` (values may be wrapped
    in doubled quotes, as the EventLog Analyzer CSV writes them - gotcha #59)."""
    return f"nullif(regexp_extract(raw, '{name}:\"+([^\";]*)', 1), '')"


RULES: list[tuple[str, str]] = _SHARED["RULES"] + [
    # M5 the firewall's own verdict: a Threat Prevention blade prevented or
    # detected (let pass) the connection. Anti-Bot's C&C verdicts are T1071
    # (DET0444); an IPS verdict on traffic from outside is an exploit attempt
    # against an internet-facing host, T1190 (Initial Access; DET0080 AN0220
    # names JNDI / deserialization payload indicators); Anti-Virus / Threat
    # Emulation carry no technique until T1105 is read.
    ("CP-MAL-2", f"""
        INSERT INTO findings
        SELECT row_id, 'CP-MAL-2', NULL,
               'Check Point ' || {_field('product')} || ' ' || upper(verdict[1]) || verdict[2:] || ': ' ||
               coalesce({_field('protection_name')}, {_field('malware_action')}, 'protection') ||
               ' (' || coalesce(srcip, '?') || ' -> ' || coalesce(dstip, '?') ||
               coalesce(', severity ' || {_field('severity')}, '') || ')',
               CASE WHEN {_field('product')} = 'Anti-Bot' THEN ['T1071']
                    WHEN {_field('product')} = 'IPS'
                         AND NOT regexp_matches(coalesce(srcip, ''), '{NON_PUBLIC_IPV4_RE}') THEN ['T1190']
                    ELSE []::VARCHAR[] END
        FROM product_events
        WHERE verdict IN ('prevent', 'detect')
          AND {_field('product')} IN {THREAT_BLADES}
    """),
]
FROM_GENERIC = _SHARED["FROM_GENERIC"]
PREPARE = _SHARED["PREPARE"]
LEVEL = {**_SHARED["LEVEL"], "CP-MAL-2": "high"}
LABELS = {**_SHARED["LABELS"], "CP-MAL-2": "threat prevention verdict"}
FAMILY = {**_SHARED["FAMILY"], "CP-MAL-2": "R3"}
EQUIVALENT = {**_SHARED["EQUIVALENT"], "CP-MAL-2": "R3002"}
SUPERSEDES = (*_SHARED["SUPERSEDES"], "R3002")
