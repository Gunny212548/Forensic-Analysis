# Gotcha #30

**30. Confidence is an Admiralty Code grade (2026-10-12).** `confidence.py`
rates each collapsed finding e.g. `B2`: letter = source reliability (B
documented mapping + acquisition digest verified; C retroactive/no digest or
a guessed field; D guessed columns; E failed integrity check; F no mapping
record; A never), number = credibility (1 same entity in another log source
of the case; 2 >=2 rule families and >=5 events; 3 otherwise; 4 no parsed
timestamp or `experimental` rule). Section 6's high/medium/low is kept and
derived (1-2 high, 3 medium, 4-6 low): on the 63-file corpus the only label
changes were 4 synthetic findings of experimental rules (medium -> low).
Reliability is added in the `/findings` route (needs manifest + custody);
the reasons show on hover in the Review tab. Verified: monsoon zip -
10.8.1.50 appears in both the firewall and ESXi members -> grade 1.
