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
- Malware & C2 by Check Point's own verdict (URL category, Threat Prevention
  blades): no Check Point category definitions were obtainable, and the export
  holds no Anti-Bot / IPS / Anti-Virus record.
"""

from . import rules_firewall

PRODUCT = "checkpoint"
_SHARED = rules_firewall.build(PRODUCT, "CP", service="coalesce(dstport, app)", unit="services")

RULES: list[tuple[str, str]] = _SHARED["RULES"]
FROM_GENERIC = _SHARED["FROM_GENERIC"]
PREPARE = _SHARED["PREPARE"]
LEVEL = _SHARED["LEVEL"]
LABELS = _SHARED["LABELS"]
FAMILY = _SHARED["FAMILY"]
EQUIVALENT = _SHARED["EQUIVALENT"]
# R3002 (a malware-like category) keeps running on Check Point rows: there is no
# Check Point category rule to replace it (the category column is not read for
# Check Point yet, so it cannot fire there either).
SUPERSEDES = _SHARED["SUPERSEDES"]
