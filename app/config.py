import os

DATA_DIR = os.environ.get("DATA_DIR", "/data")

# Every uploaded log is interpreted and stored in ONE fixed zone: GMT+7.
# A timestamp carrying an offset ("...Z", "...+00:00") is converted into it;
# a timestamp carrying none is taken to already be in it. So `raw_events.ts`
# is always GMT+7 wall-clock time, and comparing two rows from two vendors is
# always valid - which is the whole point, because the deliverable is a
# timeline. `ts_raw` still keeps the source text verbatim, and the
# `timezone-unconfirmed` flag still records that the source never stated a
# zone and this assumption was applied (FR-1.6).
#
# Two spellings of the same thing: DuckDB resolves the named zone through
# ICU, Python uses the fixed offset so the image needs no tzdata. Asia/Bangkok
# has been +07:00 with no DST since 1920, so they cannot disagree.
EVENT_TZ_NAME = "Asia/Bangkok"
EVENT_TZ_OFFSET_HOURS = 7
# Appended when a stored (naive) ts is rendered, so nothing downstream - the
# analyst, or the model writing the narrative - has to guess the zone.
EVENT_TZ_SUFFIX = "+07:00"

MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024 * 1024)))  # 2GB

# Cap on rows ingested per file; 0 = no cap. Memory is bounded by the staging
# CSV and DuckDB's reader, not by this - the BATCH_SIZE knob that used to sit
# here claimed to bound memory and had had no reader since the staging-CSV
# rewrite, so it was removed rather than left to mislead.
#
# Setting this is not free: it forces every CSV onto the Python ingest path
# (see pipeline.process_case), which decodes differently from the SQL fast
# path - different timestamp formats tried, `program`/`hostname` populated -
# so the same file can produce different findings depending on this value.
# Leave it at 0 unless you are deliberately sampling a huge file.
MAX_ROWS = int(os.environ.get("MAX_ROWS", "0"))

ANALYSIS_PROVIDER = os.environ.get("ANALYSIS_PROVIDER", "groq")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# How many distinct findings to send the model. Only the OUTPUT side is
# capped (1000 OTPM), and measurement showed the model writes the same
# ~950-token object whether it is given 8, 12 or 15 events - the extra
# input costs ~580 prompt tokens and buys real coverage. At 8 the
# successful root login (lvl 3, below the severity cut) never reached the
# model at all and went unmentioned in the narrative; at 15 it was
# described and correctly tagged T1078. See the sweep note in CLAUDE.md.
MAX_EVENTS_FOR_ANALYSIS = int(os.environ.get("MAX_EVENTS_FOR_ANALYSIS", "15"))

# qwen3.8-27b enforces a ~1000 output-tokens-per-minute cap on this tier,
# separate from (and far stricter than) the combined prompt+completion TPM
# limit. Asking for more than the cap does not raise it - it just means the
# response stops mid-JSON with finish_reason=length. Stay under it.
MAX_COMPLETION_TOKENS = int(os.environ.get("MAX_COMPLETION_TOKENS", "950"))
