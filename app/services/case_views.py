"""What a case looks like to the people and exports that read it: the custody
view, the collapsed findings with their confidence, review decision and
lifecycle status, and the one-line VERIS classification.

These lived in routers/cases.py, which made the MCP server import a FastAPI
router to get a findings list. Services read this module; routers and the
MCP server call it.
"""

from . import (areas, confidence, custody, db, finding_ids, investigation, lifecycle, provenance, related,
               review, rule_meta, storage, triage, veris)


def integrity_refused(manifest: dict) -> bool:
    """The last run was refused because the preserved file no longer matches its
    acquisition digest (pipeline._verify_evidence). The refusal comes before the
    case database is dropped, so the findings of the last good run are still there."""
    return manifest.get("status") == "failed" and str(manifest.get("error") or "").startswith("IntegrityError")


def holds_findings(manifest: dict) -> bool:
    """Whether the workflow views list this case's findings: a ready case, and a
    case refused for integrity. The second used to vanish from the Findings page,
    the badge and the Customers count while its findings were still open - the
    case most in need of attention looked like it had none. It is listed, marked
    `evidence_problem`; exports stay refused (routers/cases.py)."""
    if manifest.get("status") != "ready" and not integrity_refused(manifest):
        return False
    return db.db_path(manifest["case_id"]).exists()


def custody_view(case_id: str, manifest: dict) -> dict:
    intact, problem = custody.verify_chain(case_id)
    return {
        "evidence": manifest.get("evidence"),
        "standards": custody.STANDARDS,
        "chain_intact": intact,
        "chain_problem": problem,
        "entries": custody.entries(case_id),
    }


def ingest_view(case_id: str, manifest: dict) -> dict:
    """The Ingest step's own facts (story 3): question, provenance per evidence
    item with the time settings its last run applied, duplicates, the
    reproducibility record of the last run, and the warnings."""
    applied = {a["item"]: a for a in manifest.get("time_applied") or []}
    method = next((e.get("method") for e in reversed(custody.entries(case_id))
                   if e.get("action") == "processed" and e.get("method")), None)
    return {
        "case_id": case_id,
        "status": manifest.get("status"),
        "investigation": investigation.get(manifest),
        "items": [{"item": item,
                   "provenance": (manifest.get("provenance") or {}).get(item) or {},
                   "time_applied": applied.get(item)}
                  for item in provenance.items(manifest)],
        "fields": list(provenance.FIELDS),
        "reprocess_needed": provenance.reprocess_needed(manifest),
        "duplicate_of": manifest.get("duplicate_of") or [],
        "method": method,
        # D15 / D11 (specs/per_product_rules.md): the period each item covers
        # and what each product's areas run; absent on a case processed before.
        "periods": manifest.get("periods"),
        "detection": manifest.get("detection"),
        # D16: where each line-drawing rule put its line on this evidence.
        "lines": manifest.get("lines"),
        "warnings": ingest_warnings(manifest),
    }


def ingest_warnings(manifest: dict) -> list[str]:
    """What the Ingest step lists under itself. Warnings, never blocks (D8, D9)."""
    out = []
    if not investigation.answered(manifest):
        out.append("No question recorded for this investigation - required before the report is approved")
    if provenance.reprocess_needed(manifest):
        out.append("A declared time zone or clock offset has not been applied yet - re-process to apply it")
    for d in manifest.get("duplicate_of") or []:
        out.append(f"The same file (SHA-256) was already received as {d['case_id']} "
                   f"({d.get('original_filename') or 'unnamed'})")
    for a in manifest.get("time_applied") or []:
        if a.get("rows_without_offset") and not a.get("zone"):
            out.append(f"{a['item']}: {a['rows_without_offset']:,} events state no time zone - "
                       "GMT+7 was assumed")
    if manifest.get("status") == "ready" and manifest.get("periods") is None:
        out.append("Processed before the period and product of each file were recorded - "
                   "re-process to see them")
    for p in manifest.get("periods") or []:
        if p.get("rows_without_time"):
            out.append(f"{p['item']}: {p['rows_without_time']:,} events carry no time - they fall "
                       "on no day and in no rule's window")
    return out


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
    ai = triage.load(case_id)
    ai_items, ai_failed = ai.get("items") or {}, ai.get("failed") or {}
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
        # The AI's advice on this suggestion (triage.py), if it was reviewed; else whether it is
        # still to come or failed (specs/ai_review_coverage.md C-D2 / C-D4).
        f["ai_review"] = ai_items.get(f["key"])
        f["ai_state"] = triage.state_of(case_id, manifest, f["key"], ai_items, ai_failed)
        f["ai_error"] = ai_failed.get(f["key"]) if f["ai_state"] == "failed" else None
        # Its ATT&CK tactics, in ATT&CK's order - the Attack timeline's stages.
        f["tactics"] = rule_meta.tactics_of(f.get("mitre"))
        # The detection area its rule belongs to (areas.py) - Attack events groups by it.
        f["area"] = areas.AREA_OF.get(f["rid"])
    return findings


def decided(case_id: str) -> tuple[list[str], int]:
    """The finding groups the analyst confirmed (accepted or modified), and how many
    suggestions are not decided yet. The attack path, its risk ranking and the
    narrative's graph are drawn from the confirmed ones only (the user, 2026-10-28)."""
    state = review.current(case_id)
    confirmed, undecided = [], 0
    for f in db.collapsed_findings(case_id):
        status = (state.get(f["key"]) or {}).get("status", review.UNREVIEWED)
        if status in (review.ACCEPTED, review.MODIFIED):
            confirmed.append(f["key"])
        elif status == review.UNREVIEWED:
            undecided += 1
    return confirmed, undecided


def attack_path(case_id: str) -> dict:
    """The attack graph and risk ranking of the confirmed groups - empty while a
    suggestion is not decided (the user, 2026-10-28: the path waits for every
    decision), with how many are left."""
    confirmed, undecided = decided(case_id)
    if undecided:
        return {"graph": {"nodes": [], "edges": []}, "risk": db.risk_scores(case_id, keys=[]),
                "undecided": undecided, "confirmed": len(confirmed)}
    return {"graph": db.build_graph(case_id, keys=confirmed), "risk": db.risk_scores(case_id, keys=confirmed),
            "undecided": 0, "confirmed": len(confirmed)}


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
