# Gotcha #36

**36. VERIS classification is computed, then handed to the model
(2026-10-12).** `veris.py` builds a VERIS 1.4 incident record from the
case's high/critical findings (none -> no record, `/veris` 409): Actor is
the attacking side per rule (source for auth/scan/policy-gap rules,
*destination* for C2/malware/exfil rules whose source is the victim);
public -> `external` (variety/motive Unknown), private -> `actor.unknown`
with a note, since an internal address is not an internal person. Action
varieties map from rules; vectors from the log source (OpenSSH -> "Command
shell", VERIS's remote shell; Entra -> "Web application"). Assets are
counted as variety "Unknown" - nothing in a log says laptop vs VM host.
security_incident follows the lifecycle (Confirmed on a closed TP). There
is deliberately **no `victim`**: VERIS requires country, employee_count,
industry and government on it, which no log holds.

Validated: every record from both stores against vz-risk/veris
`verisc-merged.json` (jsonschema, Draft 4) - all valid. The prompt gets one
`summary_line()`; measured on the ESXi case with the local
`qwen2.5:7b-instruct` (Ollama, not Groq): finish `stop`, 912 completion
tokens, no missing keys, and the summary named brute force followed by use
of the stolen credentials over SSH. Known soft spot: R2006 lists *every*
source that succeeded in the burst hour, so the Entra owner's own address
can appear among `actor.external`'s notes (gotcha #13's address).
