"""Merging several line-log cases into one new case.

Split out of routers/cases.py (ADR-004): the route keeps the HTTP shape, this
module owns the rules. A refusal is a MergeRefused with the status the route
answers with, so nothing here imports FastAPI.
"""

import asyncio
import hashlib

from . import custody, db, jobs, storage
from .custody import CHUNK


class MergeRefused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _concat_raw(sources: list, dest) -> tuple[int, str, list[str]]:
    """Append raw log files byte for byte. Returns (bytes written, SHA-256 of
    the merged file, SHA-256 of each source as it was read) - the digests are
    taken in the same pass, so a source is verified on exactly the bytes that
    went into the merge (custody.py).

    Nothing is parsed: syslog/FortiGate lines are self-delimited by newlines
    and carry no cross-file state, so concatenation is the whole merge. Copied
    in chunks because a single source can be ~1GB, and deliberately not bounded
    by config.MAX_UPLOAD_BYTES - that limit guards the streaming HTTP endpoint
    against one oversized POST body, and these bytes are already on disk and
    already ingested.
    """
    size = 0
    tail = b"\n"
    merged = hashlib.sha256()
    per_source = []
    with open(dest, "wb") as out:
        for src in sources:
            # A source not ending in a newline would otherwise glue its last
            # line onto the next file's first line, losing both to the
            # decoder. `tail` starts as a newline so nothing leads the file.
            if tail != b"\n":
                out.write(b"\n")
                merged.update(b"\n")
                size += 1
            h = hashlib.sha256()
            with open(src, "rb") as fh:
                while chunk := fh.read(CHUNK):
                    out.write(chunk)
                    merged.update(chunk)
                    h.update(chunk)
                    size += len(chunk)
                    tail = chunk[-1:]
            per_source.append(h.hexdigest())
    return size, merged.hexdigest(), per_source


async def merge_cases(body: dict, actor: str) -> dict:
    """Concatenate several already-ingested line-log cases into one new case
    and run the normal pipeline over the whole thing.

    A log export tool splitting 29 hours of FortiGate traffic into 15
    hourly files meant every rule, risk score and narrative only ever saw one
    hour: sources whose policy-gap violations recurred all day reached no
    per-file threshold, and only a human cross-reading 15 AI reports noticed.
    Merging the raw files and re-running the existing single-case machinery
    buys full-window correlation without a second, cross-case query layer.
    """
    case_ids = body.get("case_ids") or []
    if not isinstance(case_ids, list) or len(case_ids) < 2:
        raise MergeRefused(400, "case_ids must be a list of at least 2 case ids")
    if len(set(case_ids)) != len(case_ids):
        # Concatenating a file with itself would double every one of its rows
        # and invent correlations that never happened.
        raise MergeRefused(400, "case_ids contains the same case more than once")

    sources, unknown = [], []
    for cid in case_ids:
        manifest = storage.load_manifest(cid)
        (sources if manifest else unknown).append(manifest or cid)
    if unknown:
        raise MergeRefused(404, f"Case not found: {', '.join(unknown)}")

    # One customer's evidence is never combined with another's - the merged
    # case lives in exactly one customer's store (storage.py). This used to
    # merge across customers and file the result under the first one.
    owners = {m.get("company_id") for m in sources}
    if len(owners) != 1 or None in owners:
        raise MergeRefused(409, "Cases of different customers cannot be merged")
    company_id = owners.pop()
    if body.get("company_id") not in (None, company_id):
        raise MergeRefused(409, "company_id must be the customer the cases belong to")

    # Only line logs for now. A CSV would contribute a header row per file
    # (and two log sources' exports need not even share a column set), and JSON
    # is either lines or one array - neither concatenates blindly.
    wrong_kind = [m["case_id"] for m in sources if m.get("file_kind") != "log"]
    if wrong_kind:
        raise MergeRefused(
            400,
            "Only file_kind='log' cases can be merged; these are not: "
            + ", ".join(wrong_kind),
        )

    # The raw upload is the audit trail, and it is also the only copy of the
    # bytes - a case whose raw file went missing cannot contribute.
    gone = [m["case_id"] for m in sources
            if not storage.raw_path(m["case_id"], "log").exists()]
    if gone:
        raise MergeRefused(409, f"Raw file missing for: {', '.join(gone)}")

    # Chronological, not upload order: the merged file must read as one
    # timeline. Manifests do not carry ts_first, so it comes from the case's
    # own DuckDB; a case that never processed (or parsed no timestamp at all)
    # falls back to upload order and is reported rather than rejected.
    ordered, fallback = [], []
    for m in sources:
        ts_first = m.get("ts_first") or db.ts_range(m["case_id"])[0]
        if not ts_first:
            fallback.append(m["case_id"])
        key = (0, ts_first) if ts_first else (1, m.get("uploaded_at") or "")
        ordered.append((key, ts_first, m))
    ordered.sort(key=lambda entry: entry[0])

    company = storage.load_company(company_id)
    if company is None:
        raise MergeRefused(404, "Company not found")
    company_name = company["name"]
    # Sources from one project stay in it. Since every new case is in a project
    # (specs/projects.md P1), sources from different projects are refused rather than
    # giving a case in none; old cases all in no project still merge into none.
    project_ids = {m.get("project_id") for m in sources}
    if len(project_ids) != 1:
        raise MergeRefused(409, "Cases of different projects cannot be merged - move them into one project first")
    project_id = project_ids.pop()
    project = storage.load_project(company_id, project_id) if project_id else None
    if project is not None and storage.project_status(project) == storage.PROJECT_CLOSED:
        raise MergeRefused(409, f"Project \"{project['name']}\" is closed - reopen it to add a merged case")

    names = [m.get("original_filename") or m["case_id"] for _, _, m in ordered]
    manifest = storage.create_case(
        original_filename=f"merged({len(ordered)}): " + "+".join(names),
        file_kind="log",
        size_bytes=0,
        note=body.get("note") or f"Merged {len(ordered)} cases in chronological order",
        company_id=company_id,
        company_name=company_name,
        project=project,
        merged_from=[
            {"case_id": m["case_id"], "original_filename": m.get("original_filename"),
             "ts_first": ts_first}
            for _, ts_first, m in ordered
        ],
    )
    case_id = manifest["case_id"]
    dest = storage.raw_path(case_id, "log")
    jobs.begin(case_id)  # a restart during the concatenation fails the case (services/jobs.py)

    # Byte-level copy in chunks: syslog lines are self-delimited and carry no
    # cross-file state, so nothing has to be parsed here, and ~1GB sources
    # must not be read into memory. config.MAX_UPLOAD_BYTES deliberately does
    # not apply - it guards the streaming HTTP endpoint against one oversized
    # POST body, and these bytes are already on disk and already ingested.
    # Off the event loop for the same reason the pipeline is: this is minutes
    # of blocking disk IO (13GB for the FortiGate set), and running it inline
    # would stall every other request for the duration.
    size, sha256, source_digests = await asyncio.to_thread(
        _concat_raw, [storage.raw_path(m["case_id"], "log") for _, _, m in ordered], dest
    )

    # A merge is derived evidence: it is only as good as its sources, so each
    # is checked against the digest recorded when it was acquired, and the
    # derivation - which files, at which digests - is the new case's first
    # custody entry.
    altered = [m["case_id"] for (_, _, m), got in zip(ordered, source_digests)
               if (m.get("evidence") or {}).get("sha256") not in (None, got)]
    if altered:
        jobs.cancel(case_id)
        dest.unlink(missing_ok=True)
        storage.manifest_path(case_id).unlink(missing_ok=True)
        raise MergeRefused(
            409, "Evidence integrity check failed - the preserved file no longer matches "
                 f"its acquisition digest for: {', '.join(altered)}")
    custody.record(
        case_id, "derived", actor, sha256=sha256, bytes=size, method="concatenation",
        sources=[{"case_id": m["case_id"], "sha256": got,
                  "verified": bool((m.get("evidence") or {}).get("sha256"))}
                 for (_, _, m), got in zip(ordered, source_digests)],
    )
    for (_, _, m), got in zip(ordered, source_digests):
        custody.record(m["case_id"], "used_in_merge", actor, sha256=got, merged_into=case_id)

    fields = {"size_bytes": size, "evidence": custody.evidence(sha256, size, actor)}
    if fallback:
        fields["merge_order_fallback"] = fallback
    storage.update_case(case_id, **fields)
    manifest.update(fields)

    jobs.submit(case_id, dest, "log")
    return manifest
