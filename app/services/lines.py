"""Where a product rule draws its line (specs/per_product_rules.md, D16, Q66-Q70).

Two methods, both read (docs/standards/SOURCES.md), and a third for what neither can see
(CUSUM over the site's failures, below - Javed & Paxson §4.1, gotcha #68):

- **TRW** - Jung, Paxson, Berger & Balakrishnan 2004, §4: for each source, the
  first attempt to each *new* destination host is a success or a failure, and
  Wald's sequential likelihood-ratio test decides scanner / benign / pending.
  The paper's parameters (Q68): a benign source succeeds with probability 0.8,
  a scanner 0.2; false alarms <= 0.01, detection >= 0.99 - which decides after
  4 failures or 4 successes. No population and no time window. A firewall
  refusal is read as a failure and an allowed connection as a success - an
  adaptation, stated: the paper's failure is an attempt to an inactive host or
  service. Any other verdict (Check Point's Detect, a sign-in) is neither.
- **Evidence line** - Javed & Paxson 2013, §3.1: measure how the evidence's own
  *legitimate* members behave and draw the line well above that tail - here
  above twice their 99th percentile (Q66). The members are chosen by a
  criterion that does not depend on the line (Q70), so attackers cannot raise
  it: a 99th percentile over everyone is raised by the attackers unless they
  are under 1% of it. Under MIN_LEGIT legitimate members no tail can be
  measured and no line is drawn (Q67): every entity showing the behaviour goes
  to the analyst. A line is never below the behaviour's own minimum.

Every rule that draws a line returns a record of it - method, value, the
population and its size - which the case keeps (manifest `lines`), so a
reader can check how each finding was decided.
"""

import math

THETA_BENIGN, THETA_SCANNER = 0.8, 0.2  # success probability of a first attempt
ALPHA, BETA = 0.01, 0.99                # false alarm bound, detection bound
TRW_UPPER = math.log(BETA / ALPHA)                # cross it: scanner
TRW_LOWER = math.log((1 - BETA) / (1 - ALPHA))    # cross it: benign
LLR_FAILURE = math.log((1 - THETA_SCANNER) / (1 - THETA_BENIGN))
LLR_SUCCESS = math.log(THETA_SCANNER / THETA_BENIGN)

MIN_LEGIT = 20  # legitimate members needed to measure a tail (Q67, gotcha #57's MIN_CROWD)
TAIL = 0.99
FACTOR = 2

TRW_SOURCE = "Jung, Paxson, Berger & Balakrishnan 2004, §4 (TRW)"
LINE_SOURCE = "Javed & Paxson 2013, §3.1 (legitimate members' tail)"


def trw(con, product: str, deny_verdicts: str, non_public_re: str) -> dict:
    """Decide every source of `product`'s rows with TRW into TEMP TABLE
    trw_<product> (srcip, decision, hosts, n_decided, episode_start).
    Idempotent per run.
    Returns the summary the case shows, with the success ratio measured on
    the sources decided benign beside the paper's 0.8 (Q68)."""
    table = f"trw_{product}"
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE {table}_walk AS
        WITH tried AS (
          SELECT srcip, dstip, ts, row_id, verdict IN {deny_verdicts} AS failed,
                 row_number() OVER (PARTITION BY srcip, dstip ORDER BY ts, row_id) AS k
          FROM raw_events
          WHERE product = '{product}' AND srcip IS NOT NULL AND dstip IS NOT NULL
            AND ts IS NOT NULL AND (verdict = 'allow' OR verdict IN {deny_verdicts})
            -- The paper tests accesses to the site's own addresses. An internal
            -- host going out to the internet is not scanning the site: a user
            -- refused at four blocked web sites in a row was a "scanner" on the
            -- Check Point quarter. Internal -> public contacts are left out.
            AND NOT (regexp_matches(srcip, '{non_public_re}')
                     AND NOT regexp_matches(dstip, '{non_public_re}')))
        SELECT srcip, dstip, ts, failed,
               row_number() OVER (PARTITION BY srcip ORDER BY ts, row_id) AS n
        FROM tried WHERE k = 1""")
    return decide(con, table)


def decide(con, table: str) -> dict:
    """Walk TEMP TABLE `<table>_walk` (srcip, failed, ts, n: each source's first
    attempt at each new target, numbered in time order) and write the decision
    of every source into TEMP TABLE `<table>`. Shared by the firewall's hosts
    (trw above) and other targets - a sign-in source's accounts (rules_windows)."""
    # The walk itself, per source in time order. **After a benign decision it
    # starts again** (the user's test, 2026-10-22): the paper decides each
    # remote host once, over 24-hour traces; over months a workstation that was
    # ordinary for weeks and then swept the server VLAN (QakBot, 85% of its new
    # hosts refused) was decided benign on its first four contacts and never
    # looked at again. Restarting the test is an adaptation, stated. A scanner
    # decision stands, with the time its episode began.
    sources, decisions, hosts, decided_n, starts = [], [], [], [], []
    for src, failed, times in con.execute(
            f"SELECT srcip, list(failed ORDER BY n), list(ts ORDER BY n) FROM {table}_walk "
            "GROUP BY srcip").fetchall():
        # `first_fail`: the episode's first refused new host - when the scan began.
        walk, start, first_fail, benign, verdict = 0.0, 0, None, False, None
        for k, f in enumerate(failed):
            walk += LLR_FAILURE if f else LLR_SUCCESS
            if f and first_fail is None:
                first_fail = k
            if walk >= TRW_UPPER:
                verdict = (k - start + 1, times[first_fail])
                break
            if walk <= TRW_LOWER:
                benign, walk, start, first_fail = True, 0.0, k + 1, None
        sources.append(src)
        hosts.append(len(failed))
        if verdict:
            decisions.append("scanner")
            decided_n.append(verdict[0])
            starts.append(verdict[1])
        else:
            decisions.append("benign" if benign else "pending")
            decided_n.append(None)
            starts.append(None)
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE {table} AS
        SELECT unnest($1::VARCHAR[]) AS srcip, unnest($2::VARCHAR[]) AS decision,
               unnest($3::BIGINT[]) AS hosts, unnest($4::BIGINT[]) AS n_decided,
               unnest($5::TIMESTAMP[]) AS episode_start""",
                [sources, decisions, hosts, decided_n, starts])
    counts = dict(con.execute(f"SELECT decision, count(*) FROM {table} GROUP BY 1").fetchall())
    measured = con.execute(
        f"SELECT avg(CASE WHEN failed THEN 0 ELSE 1 END) FROM {table}_walk "
        f"JOIN {table} USING (srcip) WHERE decision = 'benign'").fetchone()[0]
    return {
        "method": "trw", "source": TRW_SOURCE,
        "parameters": {"success_benign": THETA_BENIGN, "success_scanner": THETA_SCANNER,
                       "alpha": ALPHA, "beta": BETA},
        "sources": {k: counts.get(k, 0) for k in ("scanner", "benign", "pending")},
        "measured_success_benign": None if measured is None else round(measured, 4),
        "assumption_holds": None if measured is None else measured >= THETA_BENIGN,
    }


def evidence_line(con, legit_sql: str, minimum: float, population: str, params=None) -> dict:
    """The line over `legit_sql`'s column `v`, one row per legitimate member.
    The rule flags a value when `v > above AND v >= minimum`: `above` is twice
    the members' 99th percentile, or -1 when there are too few members to
    measure one (then the minimum alone decides - every entity showing the
    behaviour)."""
    n, tail = con.execute(
        f"SELECT count(*), quantile_cont(v, {TAIL}) FROM ({legit_sql})", params or []).fetchone()
    if n < MIN_LEGIT:
        return {"method": "no-line", "source": LINE_SOURCE, "population": population,
                "members": n, "above": -1, "minimum": minimum,
                "note": f"{n} legitimate members - under {MIN_LEGIT}, no tail can be measured; "
                        "every entity showing the behaviour goes to the analyst"}
    above = FACTOR * float(tail or 0)
    return {"method": "evidence-line", "source": LINE_SOURCE, "population": population,
            "members": n, "p99": float(tail or 0), "above": above, "minimum": minimum,
            "note": f"flagged above {FACTOR} x the 99th percentile of {n} legitimate members "
                    f"({above:g}), and at least {minimum:g}"}


# --- CUSUM over a site-wide failure count (Javed & Paxson 2013 §4.1, §5, §6) --------------
# A third method, for what no per-entity count can see - guessing spread so thin over sources
# and days that each source, account and hour looks like a mistype (B5). The site's attempts in
# time order are cut into *events* of n attempts; Y = failures per event (GFI). The normal
# distribution of Y is fitted on the evidence's own cleaned attempts (§5); CUSUM accumulates
# Z = Y - mu - k and alarms when S > H and rising; H is the smallest that gives the paper's
# in-control ARL (§6: n = 100, H = 20 "one-per-3,720 events").
CUSUM_N = 100
CUSUM_ARL = 3720
CUSUM_MAX_H = 200
# Z on a lattice of 1/4 failure: the paper picks k "so that Zn is integer-valued ... for
# convenience"; with a normal mean under one failure per event, an integer mu + k forces k far
# above delta / 2 (k = 1.25 for mu = 0.75, delta = 1) and a one-failure shift is never seen.
# Counting Z in quarters keeps k within 1/8 of delta / 2 and the chain discrete.
CUSUM_SCALE = 4
CUSUM_SOURCE = "Javed & Paxson 2013, §4.1 / §5 / §6 (CUSUM over failures per 100 attempts)"


def beta_binomial(ys: list[int], n: int) -> dict:
    """Y's distribution over 0..n, fitted by moments to the events' failure counts. A
    beta-binomial (§5: the data "exhibits more variance than we can capture using a binomial
    model"); a binomial when the counts are not over-dispersed."""
    mean = sum(ys) / len(ys)
    var = sum((y - mean) ** 2 for y in ys) / len(ys)
    p = mean / n
    if p <= 0 or p >= 1:
        pmf = [0.0] * (n + 1)
        pmf[0 if p <= 0 else n] = 1.0
        return {"pmf": pmf, "mean": mean, "var": var, "rho": 0.0, "fit": "degenerate"}
    vb = n * p * (1 - p)
    if var <= vb:
        pmf = [math.comb(n, y) * p ** y * (1 - p) ** (n - y) for y in range(n + 1)]
        return {"pmf": pmf, "mean": mean, "var": var, "rho": 0.0, "fit": "binomial"}
    # var = n p (1 - p) (1 + (n - 1) rho), rho = 1 / (alpha + beta + 1)
    rho = min((var / vb - 1) / (n - 1), 0.999)
    s = 1 / rho - 1
    a, b = p * s, (1 - p) * s

    def lbeta(x, y):
        return math.lgamma(x) + math.lgamma(y) - math.lgamma(x + y)

    pmf = [math.exp(math.lgamma(n + 1) - math.lgamma(y + 1) - math.lgamma(n - y + 1)
                    + lbeta(y + a, n - y + b) - lbeta(a, b)) for y in range(n + 1)]
    return {"pmf": pmf, "mean": mean, "var": var, "rho": rho, "fit": "beta-binomial"}


AUTOMATION_WINDOW_DAYS, AUTOMATION_MIN, AUTOMATION_ALPHA = 3, 50, 0.001


def _gamma_p(a: float, x: float) -> float:
    """The regularized lower incomplete gamma P(a, x): a series below a + 1, a continued
    fraction above (the usual numerical method)."""
    if x <= 0:
        return 0.0
    lead = math.exp(-x + a * math.log(x) - math.lgamma(a))
    if x < a + 1:
        term = total = 1.0 / a
        k = a
        while abs(term) > abs(total) * 1e-14:
            k += 1
            term *= x / k
            total += term
        return total * lead
    b, c, d = x + 1 - a, 1e300, 1.0 / (x + 1 - a)
    f = d
    for i in range(1, 500):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = 1e-300 if abs(d) < 1e-300 else d
        c = b + an / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1.0 / d
        f *= d * c
        if abs(d * c - 1) < 1e-14:
            break
    return 1.0 - lead * f


def automated(times: list) -> bool:
    """Zhang's chi-squared test as Javed & Paxson §5 apply it: are a source's attempts uniform
    over the seconds of the minute and the minutes of the hour? Two-sided at 0.001 - too uneven
    (a timer) or too even both mean automation; either clock failing is enough."""
    for unit in ("second", "minute"):
        counts = [0] * 60
        for t in times:
            counts[getattr(t, unit)] += 1
        expected = len(times) / 60
        x = sum((o - expected) ** 2 for o in counts) / expected
        cdf = _gamma_p(59 / 2, x / 2)
        if 2 * min(cdf, 1 - cdf) < AUTOMATION_ALPHA:
            return True
    return False


def cusum_arl(pmf: list[float], c: int, h: int, m: int = 1) -> float:
    """Average events to an alarm (S > h), S = max(0, S + m Y - c) from S = 0: the Markov chain
    of §4.1 over the integer states S = 0..h, solved as (I - R) x = 1. `m` is the lattice: Z is
    counted in 1/m failures (below)."""
    if sum(q for y, q in enumerate(pmf) if m * y > c) <= 0:
        return math.inf
    size = h + 1
    a = [[0.0] * size + [1.0] for _ in range(size)]
    for st in range(size):
        a[st][st] += 1.0
        for y, q in enumerate(pmf):
            if q:
                t = max(0, st + m * y - c)
                if t <= h:
                    a[st][t] -= q
    for i in range(size):   # Gaussian elimination, partial pivoting
        piv = max(range(i, size), key=lambda r: abs(a[r][i]))
        if abs(a[piv][i]) < 1e-15:
            return math.inf
        a[i], a[piv] = a[piv], a[i]
        for r in range(size):
            if r != i and a[r][i]:
                f = a[r][i] / a[i][i]
                a[r] = [x - f * z for x, z in zip(a[r], a[i])]
    return a[0][size] / a[0][0]


def cusum_h(pmf: list[float], c: int, m: int = 1, target: float = CUSUM_ARL) -> tuple[int, float]:
    """The smallest H (in 1/m failures) whose in-control ARL reaches `target` (§4.1: "choose the
    value of H that results in the closest match with the desired ARLs") - the ARL grows with H,
    so a binary search; CUSUM_MAX_H failures if none does."""
    # Doubling first: a chain far larger than needed is slow and its ARL, astronomically large,
    # loses its precision.
    lo, hi = 0, 1
    while cusum_arl(pmf, c, hi, m) < target:
        if hi >= CUSUM_MAX_H * m:
            return hi, cusum_arl(pmf, c, hi, m)
        lo, hi = hi + 1, min(2 * hi, CUSUM_MAX_H * m)
    while lo < hi:
        mid = (lo + hi) // 2
        if cusum_arl(pmf, c, mid, m) >= target:
            hi = mid
        else:
            lo = mid + 1
    return lo, cusum_arl(pmf, c, lo, m)


def cusum_run(ys: list[int], mu: float, c: int, h: int, m: int = 1) -> tuple[list[bool], list[tuple[int, int]]]:
    """D for every event (S > h and rising) and the out-of-control runs as (first, last) event:
    from the first alarm until an event at or below the normal mean, when S is reset (§4.1)."""
    st, out, first, last = 0, False, 0, 0
    flags, runs = [], []
    for i, y in enumerate(ys):
        prev, st = st, max(0, st + m * y - c)
        d = st > h and st > prev
        flags.append(d)
        if d:
            if not out:
                out, first = True, i
            last = i
        elif out and y <= mu:
            runs.append((first, last))
            out, st = False, 0
    if out:
        runs.append((first, last))
    return flags, runs
