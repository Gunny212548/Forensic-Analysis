"""LLM transport: the provider switch (Groq / Ollama), one chat call with the
per-minute-budget handling, and the errors it raises.

Split out of analysis.py (ADR-004) so that module is left with prompts, the
schema and the narrative flow. Nothing here knows what a finding is.
"""

import asyncio
import json
import re

import httpx

from .. import config


class AnalysisNotConfigured(Exception):
    pass


class AnalysisError(Exception):
    pass


class AnalysisRateLimited(Exception):
    """Groq refused the request on a per-minute token budget.

    qwen3.8-27b's 1000 OTPM cap is per minute across *all* requests, and the
    API reserves the full max_tokens up front - so one analysis of this size
    consumes almost the whole minute and a second one straight after it is
    rejected outright. That is a wait-and-retry condition, not a failure of
    the analysis, and the analyst needs to be told how long to wait.
    """

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


# Retry a rate-limited call in-place only if the wait is short enough to sit
# inside the HTTP request; anything longer goes back to the analyst as a 429
# telling them when to try again.
AUTO_RETRY_MAX_WAIT = 25.0

# A background map-reduce job is not holding an HTTP request open, so it can
# afford to sit out a full OTPM window rather than failing the whole case for
# a wait it was always going to have to do. Still bounded: anything longer
# than this is a quota problem, not a per-minute one.
BACKGROUND_RETRY_MAX_WAIT = 90.0


def _retry_after_seconds(resp) -> float | None:
    header = resp.headers.get("retry-after")
    if header:
        try:
            return float(header)
        except ValueError:
            pass
    match = re.search(r"try again in ([0-9.]+)s", resp.text)
    return float(match.group(1)) if match else None


def _is_local() -> bool:
    """True when the narrative is written by a model we host ourselves.

    Everything in this module that sleeps, paces or raises AnalysisRateLimited
    exists for Groq's 1000 OTPM reservation. A local Ollama has no such budget
    - throttling it would only make it slower for nothing - so those paths are
    skipped rather than parameterised.
    """
    return config.LLM_PROVIDER == "ollama"


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=config.LLM_TIMEOUT)


def _to_ollama(payload: dict) -> dict:
    """Translate one OpenAI-shaped request into Ollama's native /api/chat.

    Only the transport differs - same messages, same JSON-object mode, same
    temperature. What the native endpoint adds, and the only reason it is used,
    is options.num_ctx: without it the server truncates the prompt at 4096
    tokens and the system prompt is what disappears (see config.OLLAMA_API_URL).
    """
    body = {
        "model": payload["model"],
        "messages": payload["messages"],
        "stream": False,
        # Thinking-capable models (qwen3.5, gemma4) otherwise reason first and
        # that reasoning counts against num_predict: gemma4:12b spent all 2400
        # tokens thinking and returned empty content (finish "length"). The
        # "/no_think" line in the prompt is a Qwen convention other families
        # ignore; this is the API switch. Accepted by non-thinking models too.
        "think": False,
        "options": {
            # Greedy + fixed seed: the same case gives the same narrative
            # (config.OLLAMA_TEMPERATURE). The 0.2 in the payload is Groq's.
            "temperature": config.OLLAMA_TEMPERATURE,
            "seed": config.OLLAMA_SEED,
            "num_predict": payload.get("max_tokens", config.MAX_COMPLETION_TOKENS),
            "num_ctx": config.OLLAMA_NUM_CTX,
        },
    }
    if payload.get("_schema"):
        # Structured outputs: Ollama compiles the schema into a grammar and
        # decodes inside it, so an enum value is the only thing that can be
        # written there (grounding.py).
        body["format"] = payload["_schema"]
    elif (payload.get("response_format") or {}).get("type") == "json_object":
        body["format"] = "json"
    return body


def _from_ollama(body: dict) -> dict:
    """Map Ollama's native response back into the OpenAI shape, so
    _content_of/_meta/usage downstream stay provider-agnostic."""
    prompt_tokens = body.get("prompt_eval_count") or 0
    completion_tokens = body.get("eval_count") or 0
    done = body.get("done_reason") or "stop"
    return {
        "choices": [{
            "message": {"content": (body.get("message") or {}).get("content", "")},
            # Ollama says "length" when num_predict ran out - same meaning as
            # OpenAI's, and _meta.truncated still judges by missing keys.
            "finish_reason": "length" if done == "length" else done,
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "total_time": round((body.get("total_duration") or 0) / 1e9, 3),
            "num_ctx": config.OLLAMA_NUM_CTX,
        },
    }


async def _chat(client, payload: dict, auto_retry_max_wait: float = AUTO_RETRY_MAX_WAIT) -> dict:
    """One chat completion, with the per-minute-budget handling that every
    call in this module shares.

    Both providers speak the same OpenAI-compatible request/response shape, so
    the only differences are the URL, the auth header, and the fact that a
    local model cannot be rate-limited. A 429 from Groq is the OTPM
    reservation, not an error: it reserves the full max_tokens up front, so a
    second call inside the same minute is refused outright. Retry in place when
    the API says the wait is short enough, otherwise hand the wait back to the
    caller to decide - an HTTP request turns it into a 429 + Retry-After, a
    background job sleeps it off.
    """
    if _is_local():
        resp = await client.post(config.OLLAMA_API_URL, json=_to_ollama(payload))
        if resp.status_code != 200:
            raise AnalysisError(
                f"Ollama API error {resp.status_code} at {config.OLLAMA_API_URL}: "
                f"{resp.text[:500]}"
            )
        return _from_ollama(json.loads(resp.content.decode("utf-8")))

    headers = {"Authorization": f"Bearer {config.GROQ_API_KEY}"}
    # Keys starting with "_" are ours (the grounding schema); Groq stays on
    # plain JSON mode and only the after-the-fact check applies to it.
    payload = {k: v for k, v in payload.items() if not k.startswith("_")}
    resp = await client.post(config.GROQ_API_URL, headers=headers, json=payload)

    if resp.status_code == 429:
        wait = _retry_after_seconds(resp)
        if wait is not None and wait <= auto_retry_max_wait:
            await asyncio.sleep(wait + 1.0)
            resp = await client.post(config.GROQ_API_URL, headers=headers, json=payload)

    if resp.status_code == 429:
        wait = _retry_after_seconds(resp)
        when = f" Try again in about {int(wait) + 1}s." if wait else ""
        raise AnalysisRateLimited(
            f"{config.GROQ_MODEL} is out of output tokens for this minute "
            f"(1000 OTPM cap; one analysis uses most of it).{when}",
            wait,
        )

    if resp.status_code != 200:
        raise AnalysisError(f"Groq API error {resp.status_code}: {resp.text[:500]}")

    return json.loads(resp.content.decode("utf-8"))


def _content_of(body: dict) -> tuple[str, str | None]:
    finish_reason = body.get("choices", [{}])[0].get("finish_reason")
    try:
        return body["choices"][0]["message"]["content"], finish_reason
    except (KeyError, IndexError) as exc:
        raise AnalysisError(f"Could not parse {config.LLM_PROVIDER} response: {exc}") from exc


def _preflight() -> None:
    """Only the selected provider has to be configured - running local must
    not require a Groq key, and vice versa."""
    if config.LLM_PROVIDER == "ollama":
        if not config.OLLAMA_MODEL:
            raise AnalysisNotConfigured(
                "OLLAMA_MODEL is not set. Add it to .env and restart the container."
            )
        return
    if config.LLM_PROVIDER != "groq":
        raise AnalysisNotConfigured(
            f"LLM_PROVIDER is set to '{config.LLM_PROVIDER}'; supported values are 'groq' and 'ollama'."
        )
    if not config.GROQ_API_KEY:
        raise AnalysisNotConfigured(
            "GROQ_API_KEY is not set. Add it to .env and restart the container."
        )


class _OtpmPacer:
    """Spend the per-minute output-token reservation deliberately.

    Groq reserves the full max_tokens of every request against a 1000
    output-tokens-per-minute budget, so what limits a multi-call job is not
    requests per minute but reserved tokens per minute: three 300-token map
    calls fit in one minute, a 950-token reduce call does not fit beside
    anything. Sleeping out the rest of the window before a call that would
    not fit is cheaper and far more predictable than discovering it as a 429
    - which is still handled, in case this estimate is wrong.
    """

    def __init__(self, budget: int | None = None):
        self.budget = budget or config.ANALYSIS_OTPM_BUDGET
        self.window_start: float | None = None
        self.reserved = 0
        self.slept = 0.0

    async def reserve(self, tokens: int) -> None:
        if _is_local():
            return  # a model we host ourselves has no per-minute reservation
        loop = asyncio.get_running_loop()
        now = loop.time()
        if self.window_start is None or now - self.window_start >= 60.0:
            self.window_start, self.reserved = now, 0
        if self.reserved and self.reserved + tokens > self.budget:
            wait = 60.0 - (now - self.window_start) + 1.0
            if wait > 0:
                self.slept += wait
                await asyncio.sleep(wait)
            self.window_start, self.reserved = loop.time(), 0
        self.reserved += tokens

    def note_wait(self, seconds: float) -> None:
        """A 429 means the real window is behind ours; restart from now."""
        self.slept += seconds
        self.window_start, self.reserved = None, 0
