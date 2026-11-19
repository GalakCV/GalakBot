"""DeepSeek tool calling with shared deterministic budgets and offline replay.

Provider reasoning_content is kept only in conversation memory for API protocol
continuation. Traces contain explicit operational decisions, never that field.
"""
from __future__ import annotations

from collections import defaultdict, deque
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

from .core import Refused, redact


def public_message(message):
    """Remove provider-private reasoning from anything written to disk."""
    if isinstance(message, dict):
        return {k: public_message(v) for k, v in message.items() if k != "reasoning_content"}
    if isinstance(message, list):
        return [public_message(v) for v in message]
    return message


def _dict(value):
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump(exclude_none=True)
    if hasattr(value, "__dict__"):
        return vars(value)
    raise Refused("Unexpected LLM response structure")


def _number(name, default, low, high, integer=False):
    try:
        value = float(os.environ.get(name, default))
    except ValueError:
        raise Refused("Invalid numeric LLM configuration: " + name) from None
    if not math.isfinite(value) or not low <= value <= high or (integer and not value.is_integer()):
        raise Refused("LLM configuration outside allowed range: " + name)
    return int(value) if integer else value


class ReplayClient:
    """Consume recorded, redacted model replies without contacting any provider.

Replay validates the public request digest, preserving per-agent ordering even
when scheduling differs. It reproduces choices, not model sampling or live hosts.
Use fixture mode to keep the replayed tool calls offline as well.
"""
    is_replay = True

    def __init__(self, trace_path, campaign=None):
        self.responses = defaultdict(deque)
        self.lock = threading.Lock()
        rows = [json.loads(line) for line in Path(trace_path).read_text(encoding="utf-8").splitlines()]
        campaigns = [row.get("campaign") for row in rows if row.get("event") == "llm.response" and row.get("campaign")]
        selected = campaign or (campaigns[-1] if campaigns else None)
        for row in rows:
            if selected and row.get("campaign") != selected:
                continue
            if row.get("event") == "llm.response":
                self.responses[row["agent_id"]].append(row)
        if not self.responses:
            raise Refused("Replay trace contains no LLM responses")

    def response(self, agent_id, request_digest):
        with self.lock:
            queue = self.responses[agent_id]
            if not queue:
                raise Refused("Replay exhausted for agent " + agent_id)
            row = queue.popleft()
        if row.get("request_digest") != request_digest:
            raise Refused("Replay request diverged for agent " + agent_id)
        return {"choices": [{"message": row["message"]}], "usage": row.get("usage", {})}


class LLMClient:
    def __init__(self, ctx, breaker, client=None):
        self.ctx, self.breaker = ctx, breaker
        self._key = os.environ.get("DEEPSEEK_API_KEY", "")
        self.models = {
            "captain": os.environ.get("DEEPSEEK_CAPTAIN_MODEL", "deepseek-reasoner"),
            "worker": os.environ.get("DEEPSEEK_WORKER_MODEL", os.environ.get("DEEPSEEK_CAPTAIN_MODEL", "deepseek-reasoner")),
            "triager": os.environ.get("DEEPSEEK_TRIAGER_MODEL", "deepseek-chat"),
        }
        self.timeout = _number("DEEPSEEK_TIMEOUT", 30, 0.01, 120)
        self.max_output = _number("DEEPSEEK_MAX_OUTPUT_TOKENS", 2048, 1, 32768, integer=True)
        self.retries = _number("DEEPSEEK_MAX_RETRIES", 2, 0, 4, integer=True)
        # Configurable conservative token-cost estimates, not an invoice promise.
        self.prices = {
            "input": _number("DEEPSEEK_INPUT_USD_PER_MILLION", 1.32, 0, 1000),
            "cached": _number("DEEPSEEK_CACHED_INPUT_USD_PER_MILLION", 0.044, 0, 1000),
            "output": _number("DEEPSEEK_OUTPUT_USD_PER_MILLION", 3.96, 0, 1000),
        }
        self.client = client
        if client is None:
            if not self._key:
                raise Refused("DEEPSEEK_API_KEY is not set; use the deterministic fallback")
            base = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
            parsed = urlsplit(base)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise Refused("DEEPSEEK_BASE_URL must be an HTTPS endpoint without credentials")
            try:
                from openai import OpenAI
            except ImportError:
                raise Refused("Install the project dependencies to enable DeepSeek") from None
            self.client = OpenAI(api_key=self._key, base_url=base, timeout=self.timeout, max_retries=0)

    def safe(self, value):
        value = redact(value)
        if isinstance(value, dict):
            return {k: self.safe(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.safe(v) for v in value]
        if isinstance(value, str) and self._key:
            return value.replace(self._key, "[REDACTED API KEY]")
        return value

    def _remaining(self):
        self.breaker.check()
        return max(0.001, self.ctx.config["budgets"]["seconds"] - (time.monotonic() - self.breaker.started))

    def _wait(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.breaker.check()
            time.sleep(min(0.05, deadline - time.monotonic()))

    def _usage(self, value):
        raw = _dict(value) if value else {}
        # The SDK usage object uses *_tokens; traces use neutral names because
        # core.redact correctly treats arbitrary token-named application data as secret.
        def count(*names):
            for name in names:
                value = raw.get(name)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    return value
            return 0
        hit = count("prompt_cache_hit_tokens", "cache_hit")
        prompt = count("prompt_tokens", "prompt")
        miss = count("prompt_cache_miss_tokens", "cache_miss")
        if not miss:
            miss = max(0, prompt - hit)
        return dict(cache_hit=hit, cache_miss=miss, completion=count("completion_tokens", "completion"), prompt=prompt)

    def complete(self, messages, tools=None, role="captain", agent_id="captain", json_schema=None):
        if role not in self.models:
            raise Refused("Unknown LLM role")
        clean_messages = self.safe(copy.deepcopy(messages))
        clean_tools = self.safe(copy.deepcopy(tools)) if tools else None
        if json_schema is not None:
            clean_messages = [*clean_messages, {"role": "user", "content":
                "Return only JSON matching this JSON Schema: " + json.dumps(json_schema, sort_keys=True)}]
        public_request = dict(model=self.models[role], messages=public_message(clean_messages), tools=clean_tools,
                              response_format={"type": "json_object"} if json_schema is not None else None)
        encoded_public = json.dumps(public_request, sort_keys=True, ensure_ascii=False)
        # A byte-count estimate is deliberately conservative versus 4 chars/token.
        input_bound = len(json.dumps(dict(messages=clean_messages, tools=clean_tools), ensure_ascii=False).encode("utf-8")) + 1024
        if input_bound > 262144:
            raise Refused("LLM context exceeds the bounded request size")
        estimated = (input_bound * max(self.prices["input"], self.prices["cached"]) + self.max_output * self.prices["output"]) / 1_000_000
        digest = hashlib.sha256(encoded_public.encode()).hexdigest()
        kwargs = dict(model=self.models[role], messages=clean_messages, temperature=0, max_tokens=self.max_output)
        if clean_tools:
            kwargs["tools"] = clean_tools
        if json_schema is not None:
            kwargs["response_format"] = {"type": "json_object"}
        for attempt in range(self.retries + 1):
            reservation = self.breaker.reserve(cost=estimated)
            self.ctx.trace("llm.request", campaign=getattr(self, "campaign", None), agent_id=agent_id, role=role, attempt=attempt,
                           request_digest=digest, request=public_request, estimated_cost=estimated)
            try:
                if getattr(self.client, "is_replay", False):
                    response = self.client.response(agent_id, digest)
                else:
                    response = self.client.chat.completions.create(**kwargs, timeout=min(self.timeout, self._remaining()))
            except Exception as error:
                status = getattr(error, "status_code", None)
                retryable = status == 429 or (isinstance(status, int) and status >= 500) or isinstance(error, (TimeoutError, ConnectionError)) or type(error).__name__ in {"APITimeoutError", "APIConnectionError"}
                # Provider exceptions can include echoed payloads or credentials.
                # Trace only exception class/status; never exception strings.
                self.ctx.trace("llm.error", agent_id=agent_id, error_type=type(error).__name__, status=status, attempt=attempt)
                self.breaker.finish(reservation, False, status=status, cost=0.0)
                if not retryable or attempt == self.retries:
                    raise Refused("LLM request failed: " + type(error).__name__) from None
                self._wait(min(2 ** attempt, 8))
                continue
            try:
                data = _dict(response)
                choice = _dict(data["choices"][0])
                message = _dict(choice["message"])
                calls = []
                for call in message.get("tool_calls") or []:
                    call = _dict(call)
                    function = _dict(call["function"])
                    if not isinstance(call.get("id"), str) or not isinstance(function.get("name"), str) or not isinstance(function.get("arguments"), str):
                        raise Refused("Malformed LLM tool call")
                    calls.append(dict(id=call["id"], type="function", function=dict(name=function["name"], arguments=function["arguments"])))
                normalized = dict(role="assistant", content=message.get("content"), tool_calls=calls)
                if normalized["content"] is not None and not isinstance(normalized["content"], str):
                    raise Refused("Malformed LLM content")
                if message.get("reasoning_content"):
                    normalized["reasoning_content"] = message["reasoning_content"]
                normalized = self.safe(normalized)
                if len(json.dumps(normalized)) > 524288:
                    raise Refused("LLM response exceeds size limit")
                usage = self._usage(data.get("usage"))
                actual = (usage["cache_hit"] * self.prices["cached"] + usage["cache_miss"] * self.prices["input"] +
                          usage["completion"] * self.prices["output"]) / 1_000_000
                # Missing usage must not silently make paid calls free.
                if not data.get("usage"):
                    actual = estimated
            except Exception:
                self.breaker.finish(reservation, False, cost=estimated)
                raise Refused("Malformed LLM response") from None
            self.ctx.trace("llm.response", campaign=getattr(self, "campaign", None), agent_id=agent_id, role=role, request_digest=digest,
                           message=public_message(normalized), usage=usage, cost=actual)
            self.breaker.finish(reservation, True, cost=actual)
            return normalized
        raise Refused("LLM retry budget exhausted")

    def structured(self, messages, schema, role="triager", agent_id="triager"):
        try:
            from jsonschema import Draft202012Validator, ValidationError
        except ImportError:
            raise Refused("Install jsonschema to validate LLM decisions") from None
        Draft202012Validator.check_schema(schema)
        conversation = copy.deepcopy(messages)
        for attempt in range(2):
            response = self.complete(conversation, role=role, agent_id=agent_id, json_schema=schema)
            try:
                if response.get("tool_calls"):
                    raise ValueError("Decision must not contain tool calls")
                result = json.loads(response.get("content") or "")
                Draft202012Validator(schema).validate(result)
                return self.safe(result)
            except (ValueError, TypeError, ValidationError):
                self.ctx.trace("llm.invalid_json", agent_id=agent_id, attempt=attempt)
                if attempt:
                    raise Refused("LLM decision failed JSON schema validation twice") from None
                conversation.append({"role": "assistant", "content": response.get("content") or ""})
                conversation.append({"role": "user", "content": "Invalid JSON decision. Return valid JSON satisfying every schema constraint; no extra fields."})
        raise Refused("Invalid JSON decision")
