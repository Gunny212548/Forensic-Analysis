# Gotcha #28

**28. Evidence is hashed when it arrives and re-hashed before every use
(2026-10-12).** Until then nothing could show that the file analysed was the
file handed over - every finding was uncitable as evidence. `custody.py`
follows ISO/IEC 27037, NIST SP 800-86 and RFC 3227 (chain of custody), with
SHA-256 from FIPS 180-4:

- `upload_log()` hashes the bytes **as they stream to `raw/`** (compressed
  stays compressed) - no second read of a 10 GB file - and writes the
  manifest's `evidence` plus a custody `acquired` entry (who, from which
  address, size, digest).
- `pipeline.process_case()` re-hashes before every run and **refuses** on a
  mismatch (`IntegrityError`, case `failed`). It checks before `db.drop()`,
  so the last good findings are not destroyed by the refusal.
- A merge is **derived** evidence: each source is re-hashed in the same pass
  that concatenates it, the merge is refused (409) if any changed, and the
  new case's first entry lists the sources and their digests.
- `custody/{case_id}.jsonl` is append-only and **hash-chained** (each entry
  carries `prev` + its own `hash`); `GET /custody` re-checks the chain on
  every read. That detects an edit, a deletion or a reorder. It cannot stop
  someone with write access from rebuilding the whole chain - only a digest
  kept somewhere else (or an external timestamp) would.
- `client_address` is the address **the server saw**. Behind Docker's port
  mapping that can be the bridge gateway rather than the analyst's machine.

Cases uploaded before this have no acquisition digest:
`tools/backfill_custody.py --apply` hashes them now and marks the digest
`retroactive` - it attests the file from that moment, not since upload, and
the Evidence tab says so. A case without any digest is still processed, with
an `unverified` custody entry. `prune_cases.py` removes a pruned duplicate's
custody log with it (the kept copy has the same digest).

Verified 2026-10-12 by an end-to-end API run (scratch DATA_DIR, 19 checks):
digest equals the uploaded bytes, acquired -> verified -> processed, a
one-byte append is caught by verify and by re-processing, a merge with an
altered source gets 409, an edited custody line breaks the chain, backfill
marks `retroactive` and skips cases that have a digest. Host parity
unchanged (63 files).
