"""A cheap fingerprint of the files a cached result was built from.

`(mtime_ns, size)` rather than `mtime`: a coarse clock (NTFS ticks every ~15 ms,
Linux every jiffy) lets two quick writes share one mtime, but the logs these
caches watch only ever grow, so their size differs. A missing file is `(0, 0)`.
"""

from pathlib import Path


def of(*paths: Path) -> tuple:
    out = []
    for p in paths:
        try:
            st = p.stat()
            out.append((st.st_mtime_ns, st.st_size))
        except OSError:
            out.append((0, 0))
    return tuple(out)
