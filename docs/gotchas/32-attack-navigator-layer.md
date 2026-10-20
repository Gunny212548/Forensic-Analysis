# Gotcha #32

**32. A case exports as an ATT&CK Navigator layer (2026-10-12).**
`attack_layer.py` follows the Navigator's layer format 4.5 spec
(`layers/spec/v4.5/layerformat.md` in mitre-attack/attack-navigator):
`name`/`domain`/`versions` (layer "4.5", navigator "4.9.0", the spec's
minimum), one technique entry per (technique, tactic) with the Navigator's
hyphenated tactic names, `score` = the Sigma weight of the most severe
finding using it (legend included), a comment naming the rules and counts,
and the evidence SHA-256 in the layer metadata so a passed-on layer traces
back to its file. Only a `ready` case exports (409 otherwise): a failed
case can still hold findings from before an integrity refusal. Checked
against the spec's required fields, ID format and the 14 Enterprise tactic
names; it has not been loaded into the Navigator itself.
