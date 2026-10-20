# Gotcha #33

**33. Findings have a lifecycle, and only Sigma high/critical enter it
(2026-10-12).** `lifecycle.py` implements the *Finding lifecycle* decision
below (FR-4.1/4.5/4.7/4.8) aligned with NIST SP 800-61r3's CSF 2.0
outcomes: Open (RS.MA-02 triage) -> Investigating (RS.AN-03, needs an
assignee) -> Contained (RS.MI-01, containment actions required) -> Resolved
(review decision + classification + summary required; a true positive only
from Contained, benign/false positives straight from Investigating and out
of MTTC). Reopen needs a note. Every change is an entry in the hash-chained
review log (`kind: "lifecycle"`), so review state, status history and the
audit trail are one file; `review.current()` ignores those entries. MTTC =
first `processed` custody entry -> Contained, true positives only. Rules are
enforced by `POST /lifecycle`, not just the UI. Built without Jira, at the
user's word (it overlaps Sprint 3's IAI-45..49).

**The workflow threshold (gotcha #24, IAI-42) is now "Sigma level high or
critical"** - the spec's own "should trigger an internal alert and requires a
prompt review". Measured 2026-10-12 on the store: Palo Alto case 1,516
groups -> 3, monsoon zip 1,561 -> 12, Entra case 34 -> 6; on the 63-file
corpus 366 -> 39, the R3000-only files -> 0. The old "or >= 2 rule
families" clause was dropped: it admitted all 34 Entra groups (every spray
source carries R1000 + R2005), and corroboration is now the Admiralty
credibility's job (#30). This departs from the FR-4.3 wording ("Critical or
2 families"), which was written for the 0-15 scale.

Verified: 21 API checks (every refusal and the full TP and FP paths, MTTC,
chain, overview feed) on a clean scratch store, and the full flow clicked
through the UI on a scratch copy at 127.0.0.1:8097.
