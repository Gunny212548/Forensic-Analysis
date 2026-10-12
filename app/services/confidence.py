"""Finding confidence, graded with the Admiralty Code (NATO's 6x6 system).

Two independent judgements, written together as e.g. "B2":

- **Source reliability, A-F** - how far the *log source as read here* can be
  trusted. This tool's sources are machine logs, so the doubt is not about a
  device lying but about the chain between the device and the finding: was
  the file read from its documented format (logsources.py), and is it
  provably the file that was handed over (custody.py)?

    A  never given. "No doubt of authenticity ... history of complete
       reliability" is not something a parser can claim for itself.
    B  usually reliable: documented column mapping, and an acquisition digest
       that has verified on every use.
    C  fairly reliable: documented mapping, but integrity is attested only
       retroactively or not at all - or one field of the mapping was guessed.
    D  not usually reliable: the columns were guessed from their names.
    E  unreliable: the file failed its last integrity check.
    F  cannot be judged: the case predates any record of how it was read.

- **Information credibility, 1-6** - how well-supported the finding is.

    1  confirmed by other sources: the same entity is implicated in a
       *different log source* of the same case (another file of a zip) -
       independent evidence in the Admiralty sense.
    2  probably true: >=2 rule families (R1 auth / R2 correlation /
       R3 network) and >=5 supporting events - consistent evidence from one
       source. This was section 6's "high" (gotcha #20).
    3  possibly true: one rule family, or fewer than 5 events.
    4  doubtful: no parsed timestamp (cannot be placed on the timeline), or
       the rule has never been validated on real data (Sigma status
       `experimental`, rule_meta.py).
    5  improbable: not assigned automatically - an analyst's rejection
       (review.py) is where a finding is contradicted.
    6  cannot be judged: not assigned; every finding has at least a rule
       match to judge.

The requirements' high / medium / low (section 6) is kept and now derived:
1-2 high, 3 medium, 4-6 low - the same answers the old rules gave, plus
the two new cases (cross-source -> high, experimental rule -> low).

Grade wording follows the published scale (UK JWP 2-00, US FM 2-22, via
the Admiralty code reference); the mapping of this tool's facts onto the
grades is ours and is stated above, one sentence per grade.
"""

RELIABILITY = {
    "A": "Completely reliable",
    "B": "Usually reliable",
    "C": "Fairly reliable",
    "D": "Not usually reliable",
    "E": "Unreliable",
    "F": "Reliability cannot be judged",
}

CREDIBILITY = {
    1: "Confirmed by other sources",
    2: "Probably true",
    3: "Possibly true",
    4: "Doubtful",
    5: "Improbable",
    6: "Truth cannot be judged",
}


def label(credibility: int) -> str:
    """The requirements' section-6 label for a credibility grade."""
    if credibility <= 2:
        return "high"
    if credibility == 3:
        return "medium"
    return "low"


def credibility(row: dict, rule_status: str | None) -> tuple[int, list[str]]:
    """The grade one source can support (1 needs a second source - see
    annotate). `row` is a collapsed finding with ts_parsed, cnt and
    entity_families."""
    if not row["ts_parsed"]:
        return 4, ["no parsed timestamp - the finding cannot be placed on the timeline"]
    if rule_status == "experimental":
        return 4, ["the rule has not been validated on real data yet (Sigma status: experimental)"]
    independent = row["entity_families"] >= 2
    supported = row["cnt"] >= 5
    if independent and supported:
        return 2, [f"{row['entity_families']} rule families implicate this entity, "
                   f"{row['cnt']} supporting events"]
    why = []
    if not independent:
        why.append("only one rule family implicates this entity")
    if not supported:
        why.append(f"only {row['cnt']} supporting event{'s' if row['cnt'] != 1 else ''}")
    return 3, why


def _member_of(row_id: int | None, members: list[dict]) -> dict | None:
    if row_id is None:
        return None
    for m in members:
        lo, hi = m.get("row_id_first"), m.get("row_id_last")
        if lo is not None and hi is not None and lo <= row_id <= hi:
            return m
    return None


def reliability(mapping: dict | None, evidence: dict | None,
                last_check: str | None) -> tuple[str, list[str]]:
    """`last_check` is the action of the latest integrity check in the
    custody log (verified / unverified / integrity_failed), if any."""
    if last_check == "integrity_failed":
        return "E", ["the preserved file failed its last integrity check"]
    if not mapping:
        return "F", ["no record of how this file's columns were read (processed before that was kept)"]
    method = mapping.get("method")
    if method == "heuristic":
        return "D", ["columns were guessed from their names, not mapped from documentation"]
    if method == "unrecognised":
        return "F", ["no documented log format was recognised in this file"]
    why = []
    grade = "B"
    if mapping.get("heuristic_fields"):
        grade = "C"
        why.append("guessed field(s): " + ", ".join(mapping["heuristic_fields"]))
    if not evidence or not evidence.get("sha256"):
        grade = "C"
        why.append("no acquisition digest - the file cannot be shown to be the one handed over")
    elif evidence.get("retroactive"):
        grade = "C"
        why.append("integrity attested only since the digest was recorded retroactively")
    if grade == "B":
        why.append("read from documented format; digest recorded at acquisition and verified")
    else:
        why.insert(0, "read from documented format")
    return grade, why


def annotate(manifest: dict, custody_entries: list[dict], findings: list[dict],
             entity_members: dict[str, set[int]]) -> None:
    """Add the Admiralty rating to each collapsed finding in place.
    `entity_members` maps an entity to the indexes of the zip members it
    appears in (empty for a single-file case)."""
    checks = [e["action"] for e in custody_entries
              if e.get("action") in ("verified", "unverified", "integrity_failed")]
    last_check = checks[-1] if checks else None
    members = manifest.get("members") or []
    evidence = manifest.get("evidence")

    for f in findings:
        member = _member_of(f.get("sample_row_id"), members)
        mapping = member.get("mapping") if member else manifest.get("mapping")
        letter, r_why = reliability(mapping, evidence, last_check)

        grade, c_why = f.get("credibility", 3), list(f.get("credibility_reasons") or [])
        entity = f.get("srcip") or f.get("username")
        seen_in = entity_members.get(entity) or set()
        if grade <= 3 and len(seen_in) >= 2:
            names = [members[i]["name"] for i in sorted(seen_in) if i < len(members)]
            grade, c_why = 1, [f"{entity} also appears in another log source of this case: "
                               + ", ".join(names)]

        f["credibility"] = grade
        f["confidence"] = label(grade)
        f["admiralty"] = {
            "code": f"{letter}{grade}",
            "reliability": {"grade": letter, "name": RELIABILITY[letter], "why": r_why},
            "credibility": {"grade": grade, "name": CREDIBILITY[grade], "why": c_why},
        }
