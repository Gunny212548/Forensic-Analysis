"""What a case looks like to the people and exports that read it: the custody
view, the collapsed findings with their confidence, review decision and
lifecycle status, and the one-line VERIS classification.

These lived in routers/cases.py, which made the MCP server import a FastAPI
router to get a findings list. Services read this module; routers and the
MCP server call it.
"""

from . import confidence, custody, db, finding_ids, lifecycle, related, review, storage, veris


def custody_view(case_id: str, manifest: dict) -> dict:
    intact, problem = custody.verify_chain(case_id)
    return {
        "evidence": manifest.get("evidence"),
        "standards": custody.STANDARDS,
        "chain_intact": intact,
        "chain_problem": problem,
        "entries": custody.entries(case_id),
    }


def findings_view(case_id: str, manifest: dict, assign_ids: bool = True) -> list[dict]:
    """Collapsed findings with everything an analyst - or an export - sees
    on them: Admiralty confidence, review decision, lifecycle status.

    `assign_ids=False` is for a reader that must not write (the MCP server runs
    in its own process, and the id registry's lock is in-process): it shows the
    ids already handed out and leaves the rest empty."""
    findings = db.collapsed_findings(case_id)
    # Admiralty grading (confidence.py): source reliability needs the
    # manifest's mapping and evidence plus the custody log; cross-source
    # confirmation needs the zip members' row ranges.
    confidence.annotate(
        manifest, custody.entries(case_id), findings,
        db.entity_members(case_id, manifest.get("members") or []),
    )
    state = review.current(case_id)
    flow = lifecycle.state(case_id)
    # FD-YYYY-nnnn for the findings that enter the workflow (finding_ids.py),
    # and the other findings of the same attack chain (related.py).
    ids = finding_ids.ensure(case_id, manifest, findings) if assign_ids else finding_ids.lookup(case_id)
    chains = related.chains(db.finding_edges(case_id))
    for f in findings:
        f["fd"] = ids.get(f["key"])
        rel = chains.get(f["key"])
        f["related"] = rel["related"] if rel else []
        f["related_count"] = rel["related_count"] if rel else 0
        f["chain"] = rel["chain"] if rel else None
        r = state.get(f["key"])
        f["review"] = r or {"status": review.UNREVIEWED, "actor": "",
                            "reason_code": "", "note": "", "ts": None}
        # Only high/critical findings enter the workflow (lifecycle.py); the
        # rest stay visible here without a status.
        if lifecycle.tracked(f):
            lc = flow.get(f["key"]) or {"status": lifecycle.OPEN, "assignee": None, "history": []}
            f["lifecycle"] = {"tracked": True, **lc, "csf": lifecycle.CSF[lc["status"]]}
        else:
            f["lifecycle"] = {"tracked": False}
    return findings


def created_at(case_id: str, manifest: dict) -> str | None:
    """When the case's findings were created - the first time the rule
    engine finished on it (custody `processed`), else the upload time. MTTC
    is measured from here (lifecycle.py); re-processing does not reset it."""
    return custody.created_at(case_id, manifest)


def veris_line(case_id: str) -> str | None:
    """The computed VERIS classification as one prompt line (veris.py), or
    None - a failure here must never stop the narrative."""
    try:
        manifest = storage.load_manifest(case_id) or {}
        return veris.summary_line(veris.build(case_id, manifest, findings_view(case_id, manifest)))
    except Exception:  # noqa: BLE001
        return None



def source_file(manifest: dict, row_id: int) -> str | None:
    """The file a row came from. raw_events has no source column, so a zip
    case answers from each member's row_id range on the manifest; any other
    case is one file."""
    for m in manifest.get("members") or []:
        lo, hi = m.get("row_id_first"), m.get("row_id_last")
        if lo is not None and hi is not None and lo <= row_id <= hi:
            return m.get("name")
    return manifest.get("original_filename")


def _mapping_name(mapping: dict) -> str | None:
    """The log source a mapping names: a table's documented profile (`name`),
    or the message formats a line log was read by (`line_profiles`)."""
    if mapping.get("name"):
        return mapping["name"]
    names = [p["name"] for p in mapping.get("line_profiles") or [] if p.get("name")]
    if names:
        return names[0] if len(names) == 1 else f"{names[0]} (+{len(names) - 1})"
    return None


def log_type(manifest: dict, row_id: int | None = None) -> str:
    """What kind of log this is, in the words of the documentation it was read
    by (logsources.py), else the file kind.

    A zip has no mapping of its own - each member carries one - so the member
    holding `row_id` answers; with no row, the distinct names of its members."""
    members = manifest.get("members") or []
    if members:
        if row_id is not None:
            for m in members:
                lo, hi = m.get("row_id_first"), m.get("row_id_last")
                if lo is not None and hi is not None and lo <= row_id <= hi:
                    return _mapping_name(m.get("mapping") or {}) or m.get("kind") or "unknown"
        names = list(dict.fromkeys(n for m in members if (n := _mapping_name(m.get("mapping") or {}))))
        if names:
            return names[0] if len(names) == 1 else f"{names[0]} (+{len(names) - 1})"
    return _mapping_name(manifest.get("mapping") or {}) or manifest.get("file_kind") or "unknown"


def finding_sources(case_id: str, manifest: dict, key: str, limit: int, offset: int = 0) -> dict:
    """The events behind one finding, each with the file it came from - how a
    finding is traced back to its source (FR-4.1)."""
    res = db.finding_rows(case_id, key, limit, offset)
    for row in res["rows"]:
        row["source_file"] = source_file(manifest, row["row_id"])
    return {
        "case_id": case_id,
        "finding_key": key,
        "source_file": manifest.get("original_filename"),
        "evidence_sha256": (manifest.get("evidence") or {}).get("sha256"),
        "total": res["total"],
        "limit": limit,
        "offset": offset,
        "rows": res["rows"],
    }
