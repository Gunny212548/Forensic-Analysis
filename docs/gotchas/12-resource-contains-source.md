# Gotcha #12

**12. "Resource" contains "source".**
`decode.match_column()`'s loose pass matched Azure AD's `Resource` column for
`srcip`, so an entire sign-in export decoded with resource names where its IPs
belonged, and `Multifactor authentication result` (a paragraph of prose) as its
`verdict`. Fixed by `_AVOID_SUBSTRINGS` (`resource`, plus `destination`/`source`
cross-guards now that `ip address` is a srcip candidate) and by putting
`status` ahead of `result` in the verdict candidates. Same family as gotcha #2 —
when adding a candidate substring, check what else in a real header contains it.
