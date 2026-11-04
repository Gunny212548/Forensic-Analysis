"""How much time each evidence item covers (specs/per_product_rules.md, D15).

An export may hold six months to a year of events, and a rule counts a
behaviour inside a time window, never over the whole file - so the case must
say, per evidence item (each file, each zip member), what period it covers:
first and last event, the span in days, the days that hold events, the gaps
(runs of days with none) and events per day. A gap is a fact, not a
conclusion: it can be a quiet period, a log that was not collected or a
filtered export (NIST SP 800-92 §2.3, missing log content) - the analyst asks
which.

Days are calendar days of the stored event time, which ingest normalised to
GMT+7 (gotcha #21), after the item's declared zone and clock offset
(pipeline._apply_declared_time).
"""

from datetime import date
from statistics import median

LONGEST_GAPS = 10  # the gaps listed by length; all are counted


def measure(con, where: str = "TRUE", params: list | None = None) -> dict:
    """The period of the rows matching `where` (an item's row range)."""
    params = params or []
    rows, timed = con.execute(
        f"SELECT count(*), count(ts) FROM raw_events WHERE {where}", params).fetchone()
    days = con.execute(
        f"SELECT CAST(ts AS DATE) AS d, count(*) FROM raw_events "
        f"WHERE {where} AND ts IS NOT NULL GROUP BY d ORDER BY d", params).fetchall()
    first, last = con.execute(
        f"SELECT min(ts), max(ts) FROM raw_events WHERE {where}", params).fetchone()
    return summarise(rows, timed, first, last, days)


def summarise(rows: int, timed: int, first, last, days: list[tuple[date, int]]) -> dict:
    out = {"rows": rows, "rows_without_time": rows - timed,
           "first": first.isoformat(sep=" ") if first else None,
           "last": last.isoformat(sep=" ") if last else None,
           "span_days": 0, "active_days": len(days), "gap_count": 0, "gap_days": 0,
           "longest_gaps": [], "events_per_day": None}
    if not days:
        return out
    out["span_days"] = (days[-1][0] - days[0][0]).days + 1
    gaps = []
    for (d1, _), (d2, _) in zip(days, days[1:]):
        missing = (d2 - d1).days - 1
        if missing > 0:
            gaps.append({"from": date.fromordinal(d1.toordinal() + 1).isoformat(),
                         "to": date.fromordinal(d2.toordinal() - 1).isoformat(),
                         "days": missing})
    out["gap_count"] = len(gaps)
    out["gap_days"] = sum(g["days"] for g in gaps)
    out["longest_gaps"] = sorted(gaps, key=lambda g: (-g["days"], g["from"]))[:LONGEST_GAPS]
    counts = [n for _, n in days]
    out["events_per_day"] = {"min": min(counts), "median": median(counts), "max": max(counts)}
    return out
