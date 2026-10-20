# Gotcha #15

**15. Beaconing is a *regularity* test, and it only works on egress.**
`R2007` measures the interval between consecutive connections for each
src->dst pair and flags pairs whose intervals barely vary (jitter =
stddev/mean). Nothing threshold-based can express this: on the customer's
compromised host `R3000` flagged 12,281 rows and buried the four
destinations that mattered.

Calibrated on real data, not guessed: the true beacons sat at jitter
0.43-0.55 (300-450 connections at ~40-minute intervals over 11 days to
`72.154.7.0/24`, all `ssl`, all allowed) and ordinary bursty browsing at
0.89-0.94. The cut at 0.6 separates them with room on both sides.

**The egress restriction is not optional.** The first version, without it,
added 16,599 findings to one previously-clean file - all of them Windows
Delivery Optimization peer-to-peer updates (`ms-update-optimization-p2p`,
port 7680, 10.x -> 10.x, 44 host pairs). Internal traffic is periodic by
nature. Requiring a public IPv4 destination dropped every false positive and
kept the true one; the cost is that internal C2 and lateral beaconing are out
of scope. Even on egress, a legitimate update-check or telemetry endpoint is
indistinguishable from C2 in the logs alone - the rule localises, the analyst
identifies the destination.
