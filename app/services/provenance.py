"""Where each evidence item came from, and what its clock said (story 3, I3-I7).

RFC 3227 sec. 4.1 asks who collected the evidence, where and when; ACPO 5.10.3
asks "how it came to be there". An exported log answers neither by itself, so
the analyst records it: the source system, how it was exported (the query or
filter - gotcha #9: a filtered export silences correlation rules), by whom and
when, the source's time zone and a known clock offset. Every field is optional
(D9) and never a block.

An evidence item is the uploaded file, or one member of a zip (a zip is one
case of several items). `manifest["provenance"]` maps item name -> fields; the
item name is the upload's file name, or the member's name inside the zip.
Every change is a custody line with each field's old and new value, so the
hash-chained custody log (custody.py) is the history and the manifest only the
current state.

Since 2026-10-27 the screen asks for none of it: the where-from fields went
first (too much), then the time fields (not needed - most logs state their
zone; a case of 191 Windows files listed 191 "nothing to set" lines). Every
field is still accepted by PUT /provenance and kept where recorded, and a
declared zone or offset is still applied on re-process.

Time (D10). A declared zone replaces the GMT+7 assumption (gotcha #21) for the
events whose source text states no offset; a declared clock offset shifts every
event of the item. Both take effect on the next re-process - `raw_events` is
rebuilt from `raw/` on every run, so nothing here edits evidence - and the run
records what it applied in `manifest["time_applied"]`. Zones are UTC offsets
only (Q35): the Python side has no tzdata, and a named zone with DST would
mean a different offset for different rows.
"""

import re
from datetime import timedelta

from . import custody, storage
from .. import config

FIELDS = ("source_system", "export_method", "exported_by", "exported_at",
          "source_timezone", "clock_offset_seconds", "note")
_TEXT_LIMIT = {"source_system": 200, "export_method": 1000, "exported_by": 200,
               "exported_at": 64, "note": 2000}
_ZONE = re.compile(r"^([+-])(0\d|1[0-4]):([0-5]\d)$")
# A clock more than a week out is a typo, not a drift.
MAX_CLOCK_OFFSET = 7 * 24 * 3600


def items(manifest: dict) -> list[str]:
    """The evidence items of a case: the zip's members, else the file."""
    members = [m["name"] for m in manifest.get("members") or [] if m.get("name")]
    return members or [manifest.get("original_filename") or ""]


def zone_minutes(zone: str) -> int:
    """'+05:30' -> 330, '-03:00' -> -180."""
    sign, hours, minutes = _ZONE.match(zone).groups()
    return (1 if sign == "+" else -1) * (int(hours) * 60 + int(minutes))


def _clean(fields: dict) -> dict:
    """Validated values; an empty value clears the field. Raises ValueError."""
    out = {}
    for name, value in fields.items():
        if name not in FIELDS:
            raise ValueError(f"unknown provenance field '{name}' - fields are {', '.join(FIELDS)}")
        if value is None or (isinstance(value, str) and not value.strip()):
            out[name] = None
        elif name == "source_timezone":
            zone = str(value).strip()
            if not _ZONE.match(zone):
                raise ValueError("source_timezone must be a UTC offset such as +00:00 or -05:00")
            out[name] = zone
        elif name == "clock_offset_seconds":
            try:
                seconds = int(value)
            except (TypeError, ValueError):
                raise ValueError("clock_offset_seconds must be a whole number of seconds") from None
            if abs(seconds) > MAX_CLOCK_OFFSET:
                raise ValueError(f"clock_offset_seconds is more than {MAX_CLOCK_OFFSET} (a week)")
            out[name] = seconds or None
        else:
            text = str(value).strip()
            if len(text) > _TEXT_LIMIT[name]:
                raise ValueError(f"{name} is longer than {_TEXT_LIMIT[name]} characters")
            out[name] = text
    return out


def save(case_id: str, item: str | None, fields: dict, actor: str) -> dict:
    """Record provenance for one evidence item. Only the fields given change.
    Returns the item's provenance and whether a re-process is needed for its
    time settings to apply."""
    manifest = storage.load_manifest(case_id)
    names = items(manifest)
    if item is None and len(names) == 1:
        item = names[0]
    if item not in names:
        raise LookupError(f"no evidence item '{item}' in this case - items are {names}")
    clean = _clean(fields)
    with storage._case_lock(case_id):
        manifest = storage.load_manifest(case_id)
        provenance = manifest.get("provenance") or {}
        current = dict(provenance.get(item) or {})
        changes = {k: [current.get(k), v] for k, v in clean.items() if current.get(k) != v}
        if changes:
            current.update(clean)
            provenance[item] = {k: v for k, v in current.items() if v is not None}
            # The custody line first: a change that is not in the chain did not happen.
            custody.record(case_id, "provenance", actor, item=item, changes=changes)
            manifest["provenance"] = provenance
            storage.save_manifest(manifest)
    return {"item": item, "provenance": (manifest.get("provenance") or {}).get(item) or {},
            "changed": sorted(changes), "reprocess_needed": reprocess_needed(manifest)}


def declared_time(manifest: dict, item: str) -> tuple[int | None, int]:
    """(declared zone in minutes or None, clock offset in seconds) for one item."""
    p = (manifest.get("provenance") or {}).get(item) or {}
    zone = p.get("source_timezone")
    return (zone_minutes(zone) if zone else None), int(p.get("clock_offset_seconds") or 0)


def shift(zone: int | None, clock_offset: int) -> timedelta:
    """What to add to a stored GMT+7 time read from a source with this zone and
    clock: the zone's distance to GMT+7, minus how far the clock was ahead."""
    to_gmt7 = timedelta(minutes=config.EVENT_TZ_OFFSET_HOURS * 60 - zone) if zone is not None else timedelta()
    return to_gmt7 - timedelta(seconds=clock_offset)


def reprocess_needed(manifest: dict) -> bool:
    """A declared zone or clock offset that the last run did not apply."""
    applied = {a["item"]: (a.get("zone"), a.get("clock_offset_seconds") or 0)
               for a in manifest.get("time_applied") or []}
    for item in items(manifest):
        p = (manifest.get("provenance") or {}).get(item) or {}
        wanted = (p.get("source_timezone"), int(p.get("clock_offset_seconds") or 0))
        if wanted != applied.get(item, (None, 0)):
            return True
    return False


