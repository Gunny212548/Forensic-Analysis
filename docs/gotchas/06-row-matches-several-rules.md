# Gotcha #6

**6. A row can legitimately match several rules.**
Rules `INSERT` independently, so one row may produce multiple findings
(a login failure that is also part of a brute-force burst is both).
`flagged_count` counts `DISTINCT row_id` — don't switch it to `count(*)`.
