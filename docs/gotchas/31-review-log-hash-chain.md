# Gotcha #31

**31. The review log is hash-chained too, and old decisions are sealed, not
rewritten (2026-10-12).** `hashchain.py` is the chain custody.py had,
shared: `review.append()` and `custody.record()` both go through it. Review
files written before carry unchained lines; the first chained decision's
`prev` is `seal:<SHA-256 of every byte before it>`, so from then on an edit
to an old decision is caught ("the earlier unchained entries were
changed"). The store's 2 review files are unsealed until their next
decision, and the Review tab says so. A custody log is chained from line 1,
so `custody.verify_chain()` treats any unchained line in it as a problem.
Verified: the custody logs written by the old code still verify, the
custody E2E (19 checks) passes on the refactor, and a seal/edit/delete/
append test set passes.
