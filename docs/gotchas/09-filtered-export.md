# Gotcha #9

**9. A filtered export changes which rules can fire.**
The Check Point sample was exported after filtering SmartLog to one source
IP, so it contained exactly one `srcip` and ~18 minutes of traffic (the
console reported 96,418 matching rows; the CSV had 45,209). Consequences:
"100% of traffic is malicious" is an artifact of the filter, not a finding,
and a source-filtered or action-filtered export can silence correlation
rules entirely — `R2004` only works because both the allowed and blocked
rows for that IP were present. Ask what filter produced the file before
reading anything into cross-source comparisons.
