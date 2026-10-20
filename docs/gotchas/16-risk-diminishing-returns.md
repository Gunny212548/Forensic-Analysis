# Gotcha #16

**16. Risk ranking needs diminishing returns, or it just ranks by volume.**
`db.risk_scores()` accumulates finding severity per entity (source,
destination, account) the way modern SIEM risk-based alerting does, because
"which rule fired" does not answer "where do I look first" in a case with
25,579 findings. A flat `sum(lvl)` ranked a scanned host with three noisy
rules (79,500) *above* the actual C2 destination. Scoring per distinct rule
with a log-dampened count - `sum(lvl * (1 + ln(n)))` - puts the three
beaconing destinations on top instead, because it measures how many
different ways an entity is implicated rather than how much traffic it moved.
The ranking is sent to the model (it leads the summary with it) and rendered
in the analysis panel.
