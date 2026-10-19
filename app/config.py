import os

DATA_DIR = os.environ.get("DATA_DIR", "/data")

# Login accounts and the session secret live apart from customer data
# (2026-10-14, CLAUDE.md gotcha #41): resetting, backing up or handing over
# DATA_DIR never touches who can sign in, and the two can be permissioned
# separately. The default is a sibling of DATA_DIR - /data -> /auth, which
# docker-compose mounts as its own volume - rather than a fixed path, so a
# test that points DATA_DIR at a scratch store gets a scratch auth store
# beside it and can never write a throwaway account into the real one.
AUTH_DIR = os.environ.get("AUTH_DIR") or os.path.join(
    os.path.dirname(os.path.abspath(DATA_DIR.rstrip("/\\") or "/")) or "/", "auth")

# Every uploaded log is interpreted and stored in ONE fixed zone: GMT+7.
# A timestamp carrying an offset ("...Z", "...+00:00") is converted into it;
# a timestamp carrying none is taken to already be in it. So `raw_events.ts`
# is always GMT+7 wall-clock time, and comparing two rows from two log sources is
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

# Login (FR-1, app/services/auth.py). A session lasts one working shift;
# SESSION_SECRET signs the cookie and, when unset, is generated once and kept
# in AUTH_DIR so sessions survive a container restart.
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "12"))

# How many cases the pipeline processes at once (services/jobs.py). More wait
# in a queue: each ingest holds a DuckDB and a file stream, and ten at once is
# an out-of-memory kill rather than ten times the speed.
JOB_WORKERS = max(1, int(os.environ.get("JOB_WORKERS", "2")))

# The Overview compares mean time to contain (finding created -> Contained, true
# positives only) with this target, in hours (IAI-65).
MTTC_TARGET_HOURS = float(os.environ.get("MTTC_TARGET_HOURS", "4"))
# Where "can't sign in?" points on the login page (FR-1.2) - a mailto: or a
# helpdesk URL. Empty shows the instruction without a link.
IT_CONTACT_URL = os.environ.get("IT_CONTACT_URL", "")

# FR-2.2: 10 GB per file, measured after decompression (see routers/upload.py).
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024 * 1024)))  # 10GB
# FR-2.2: refuse an upload unless the data disk has this many times its size
# free. An upload is on disk twice before it is processed (Starlette's spool
# file + the raw copy), then DuckDB adds its own, so 2.5x is not padding.
UPLOAD_DISK_FACTOR = float(os.environ.get("UPLOAD_DISK_FACTOR", "2.5"))

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

# Which LLM writes the narrative. 'groq' is the hosted qwen3.8-27b every
# budget note below was measured against; 'ollama' is a local model served on
# the host through Ollama's OpenAI-compatible surface, which has no API key,
# no rate limit and no per-minute output-token reservation - so every knob
# that exists to survive Groq's OTPM cap is bypassed for it (see
# analysis._chat / _is_local). Defaults to the legacy ANALYSIS_PROVIDER value
# so an existing deployment behaves exactly as before.
LLM_PROVIDER = (os.environ.get("LLM_PROVIDER") or ANALYSIS_PROVIDER or "groq").strip().lower()

# Ollama runs on the Docker *host*, not in this container, so the default is
# the host gateway name Docker Desktop resolves. Verified reachable from the
# container without any compose network change.
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b-instruct")
# Ollama's NATIVE chat endpoint, not its OpenAI-compatible /v1 one, and the
# reason is not style: /v1/chat/completions has no way to set the context
# window, ignores an "options" block if you send one anyway, and silently
# truncates the prompt to the server default of 4096 - measured here as a
# 12,809-character prompt arriving as 2,050 tokens with the SYSTEM prompt (the
# first message, so the first thing dropped) gone. The model then answered
# off-schema and every top-level key went missing. The native endpoint takes
# options.num_ctx, and _chat maps its response back into the OpenAI shape the
# rest of this module already parses.
OLLAMA_API_URL = f"{OLLAMA_BASE_URL}/api/chat"
# Big enough for the 50-event prompt (~4k tokens) plus the output budget with
# room to spare. KV cache for qwen2.5-7b at this size is ~1GB, which fits
# beside the 4.7GB of weights on an 8GB card.
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "16384"))
# A local 7B on a consumer GPU generates at tens of tokens/sec and has to load
# the model on the first call, so the 90s that is generous for Groq is not.
OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "600"))

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

# --- local (Ollama) budgets ------------------------------------------------
# The two numbers above are Groq's constraints, not the schema's: 15 events and
# 950 output tokens are where qwen3.8-27b's 1000 OTPM cap lands. A local model
# pays no per-minute tax, so both were re-swept against qwen2.5:7b-instruct
# (see CLAUDE.md gotcha #5). Result: 50 events / 2400 tokens still returns a
# complete object, and one call takes ~30-60s instead of a minute of waiting
# for budget. These apply ONLY when LLM_PROVIDER=ollama.
OLLAMA_MAX_EVENTS_FOR_ANALYSIS = int(os.environ.get("OLLAMA_MAX_EVENTS_FOR_ANALYSIS", "50"))
OLLAMA_MAX_COMPLETION_TOKENS = int(os.environ.get("OLLAMA_MAX_COMPLETION_TOKENS", "2400"))
OLLAMA_MAP_COMPLETION_TOKENS = int(os.environ.get("OLLAMA_MAP_COMPLETION_TOKENS", "600"))
# Reproducible narrative (grounding.py): greedy decoding with a fixed seed, so
# the same case, model and prompt give the same text - an evidence report
# that changes on every click cannot be cited. Verified on Ollama 0.34.1:
# two runs at temperature 0 / seed 42 were byte-identical.
OLLAMA_TEMPERATURE = float(os.environ.get("OLLAMA_TEMPERATURE", "0"))
OLLAMA_SEED = int(os.environ.get("OLLAMA_SEED", "42"))

# --- map-reduce narrative (large cases only) -------------------------------
# A case with more distinct findings than MAX_EVENTS_FOR_ANALYSIS cannot be
# narrated from one slice, and the events-per-call ceiling is already at its
# measured maximum (raising it just truncates the JSON). So the evidence pool
# is read in batches, each summarised by a cheap call, and one final call
# writes the real schema from those summaries plus the SQL-derived context.
#
# The pool stays bounded on purpose: top_distinct_findings() has already
# collapsed and ranked by severity then volume in SQL, so "the top
# MAX_EVENTS_FOR_ANALYSIS * ANALYSIS_MAP_MAX_CHUNKS findings" is the most
# important evidence, not an arbitrary prefix. 5 chunks = 5 map calls + 1
# reduce; at ~1 call/minute that is the ceiling on how long an analyze job may
# run before an analyst gives up on it.
ANALYSIS_MAP_MAX_CHUNKS = int(os.environ.get("ANALYSIS_MAP_MAX_CHUNKS", "5"))

# Output budget for ONE map call. The map schema is a chunk note plus at most
# 4 notable events - far smaller than the full narrative schema - so several
# map calls fit inside one minute's OTPM reservation where two full analyses
# never could.
MAP_COMPLETION_TOKENS = int(os.environ.get("MAP_COMPLETION_TOKENS", "300"))

# The per-minute output-token budget Groq reserves against. Used only to pace
# the map phase so it asks for a call it can actually get; a 429 is still
# handled if the estimate is wrong.
ANALYSIS_OTPM_BUDGET = int(os.environ.get("ANALYSIS_OTPM_BUDGET", "1000"))


# --- effective per-provider settings ---------------------------------------
# Resolved once here rather than branched at every call site, so everything
# downstream (analysis.plan_map_reduce, the /analyze fast path, the prompt
# builder) keeps reading the same names and the provider switch stays a
# one-line config change. LLM_MODEL/LLM_API_URL are what _meta records.
if LLM_PROVIDER == "ollama":
    LLM_MODEL = OLLAMA_MODEL
    LLM_API_URL = OLLAMA_API_URL
    LLM_TIMEOUT = OLLAMA_TIMEOUT
    MAX_EVENTS_FOR_ANALYSIS = OLLAMA_MAX_EVENTS_FOR_ANALYSIS
    MAX_COMPLETION_TOKENS = OLLAMA_MAX_COMPLETION_TOKENS
    MAP_COMPLETION_TOKENS = OLLAMA_MAP_COMPLETION_TOKENS
else:
    LLM_MODEL = GROQ_MODEL
    LLM_API_URL = GROQ_API_URL
    LLM_TIMEOUT = float(os.environ.get("GROQ_TIMEOUT", "90"))
