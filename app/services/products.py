"""Which product an evidence item came from, and what each product's rules
cover (specs/per_product_rules.md, D10-D12, story 1).

Every file is identified before it is read (identify.py) as one documented log
source profile. A profile belongs to one product, and a product is one of the
two log types the user set (D10): **firewall** or **os**. Each product gets its
own rule set over the same six areas (areas.py, D12); a cell its log cannot
support is "not applicable" with the reason written here - never a silent 0.

The product is written on every row of `raw_events` after ingest (pipeline.
mark_products), so a rule that declares a product (rules.RULE_PRODUCT) runs on
that product's rows only, and a zip mixing a Palo Alto export and an auth.log
runs each product's rules on its own member.

Log sources that are neither a firewall nor an operating system (Entra ID
sign-ins, Exchange message trace) have a product but no type: D10 names two
types, and which one they belong to is the user's call.
"""

from . import areas

FIREWALL, OS = "firewall", "os"

# product id -> name, log type, the identification profiles (identify.py) that are it.
PRODUCTS: dict[str, dict] = {
    "paloalto": {"name": "Palo Alto Networks PAN-OS", "type": FIREWALL,
                 "profiles": ("paloalto-traffic",)},
    "checkpoint": {"name": "Check Point", "type": FIREWALL,
                   "profiles": ("checkpoint-smartconsole", "checkpoint-log-exporter")},
    "fortigate": {"name": "Fortinet FortiGate", "type": FIREWALL,
                  "profiles": ("fortigate-traffic",)},
    "cisco": {"name": "Cisco Secure Firewall", "type": FIREWALL, "profiles": ()},  # no reader yet
    "windows": {"name": "Microsoft Windows", "type": OS,
                "profiles": ("windows-event-xml", "windows-evtx", "windows-splunk-text",
                             "windows-winlogbeat-json", "windows-nxlog-json")},
    "linux": {"name": "Linux", "type": OS, "profiles": ("openssh-sshd", "linux-pam")},
    "esxi": {"name": "VMware ESXi", "type": OS,
             "profiles": ("vmware-esxi", "vmware-esxi-observed")},
    "entra": {"name": "Microsoft Entra ID", "type": None,
              "profiles": ("entra-signin", "entra-signin-azure-monitor")},
    "exchange": {"name": "Microsoft Exchange Online", "type": None,
                 "profiles": ("exchange-message-trace",)},
}

_OF_PROFILE = {p: pid for pid, prod in PRODUCTS.items() for p in prod["profiles"]}

# Cells a product's log cannot support, with the reason (D12). Only what the
# design settled; a product with no rule and no reason for an area reads
# "no rule yet", which is a gap in this tool, not in the log.
NOT_APPLICABLE: dict[tuple[str, str], str] = {
    ("paloalto", "authentication"):
        "A Palo Alto Traffic log records sessions, not sign-ins (Q61); needs a GlobalProtect "
        "or Authentication log",
    ("paloalto", "account-attacks"):
        "A Palo Alto Traffic log records sessions, not sign-ins (Q61); needs a GlobalProtect "
        "or Authentication log",
    # specs/windows_rules.md: the Security and Sysmon logs record no refused
    # connection (the Filtering Platform's 5157 would - not read yet) and no byte count.
    ("windows", "scanning-policy"):
        "Windows Security and Sysmon logs record no refused connection (the Filtering Platform's "
        "5157 would; not read yet)",
    ("windows", "data-apps"):
        "Windows Security and Sysmon logs carry no byte counts",
}


def of_profile(profile: str | None) -> str | None:
    """The product of an identification profile; None for a file not read."""
    return _OF_PROFILE.get(profile or "")


def matrix(present: list[str], rule_product: dict[str, str],
           superseded: dict[str, set[str]] | None = None) -> list[dict]:
    """Per product present in the case, what each of the six areas runs.

    `rule_product` is rules.RULE_PRODUCT (rule id -> product). A rule that
    declares no product is generic and runs on every row except those of the
    products whose own rules supersede it (`superseded`, rules.RULE_SUPERSEDED,
    story 4) - so it counts for every other product."""
    superseded = superseded or {}
    out = []
    for pid in present:
        prod = PRODUCTS.get(pid, {"name": pid, "type": None})
        cells = []
        for area in areas.AREAS:
            reason = NOT_APPLICABLE.get((pid, area["id"]))
            rids = [r for r in area["rids"]
                    if rule_product.get(r) == pid
                    or (r not in rule_product and pid not in superseded.get(r, ()))]
            if reason:
                cells.append({"area": area["id"], "name": area["name"], "status": "n/a",
                              "reason": reason, "rules": []})
            elif rids:
                cells.append({"area": area["id"], "name": area["name"], "status": "rules",
                              "rules": rids,
                              "generic": [r for r in rids if r not in rule_product]})
            else:
                cells.append({"area": area["id"], "name": area["name"], "status": "none",
                              "reason": "No rule for this product yet", "rules": []})
        out.append({"product": pid, "name": prod["name"], "type": prod["type"], "areas": cells})
    return out
