# Gotcha #34

**34. A case exports as a STIX 2.1 bundle (2026-10-12).** `stix_export.py`:
identity (tool, customer), attack-pattern per technique (mitre-attack
external ref), ipv4/ipv6/user-account SCOs with the spec's deterministic
UUIDv5 ids, per collapsed finding an observed-data plus one sighting per
technique (`confidence` = Admiralty credibility via STIX 2.1's mapping
1->90 .. 5->10, 6 omitted), and one report naming the evidence SHA-256.
Findings with no ATT&CK tag (R1001/R1003/R1004) are left out and counted in
the report. SDO ids are UUIDv5 over case + finding, so re-exports update
rather than duplicate. Shares `_findings_view()` with `/findings`.

**How it was validated, and a trap:** the OASIS `stix2-validator` 3.3.1
(pip, scratch venv, host Python 3.14) rejects *every* bundle - including one
built by the `stix2` library itself - with "Cannot locate a schema ...
cyber-observable-core.json": its install ships no schemas. Don't read that as
a bundle bug. What was used instead: `stix2.parse(..., allow_custom=False)`
(strict, all three store cases parse, no dangling refs, SCO ids equal the
library's own computation), and every object checked with `jsonschema`
against the official `oasis-open/cti-stix2-json-schemas` - all valid, and a
deliberately broken bundle is caught (missing `sighting_of_ref`, bad
timestamp).
