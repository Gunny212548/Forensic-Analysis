# Gotcha #2

**2. Exact column-name matches must beat substring matches when decoding CSV.**
Palo Alto exports have both `Action` (allow/deny — the one that matters) and
`Log Action` (value: "Log Forwarding ALL"). A naive substring search finds
`Log Action` first, `verdict` becomes garbage, and *every* firewall rule
silently stops matching — the case processes "successfully" with 0 findings.
`decode._find_field()` tries exact matches first for this reason.
