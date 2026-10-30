"""DeepSeek client (OpenAI-compatible Chat Completions API) with streaming, tool calls and thinking mode."""
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

THINKING_LEVELS = ("off", "low", "high", "max")


class APIError(Exception):
    pass


class ChatClient:
    def __init__(self, base_url, api_key, model, thinking="high"):
        parsed = urlparse(base_url)
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1', '::1')):
            raise ValueError('API endpoint requires HTTPS (HTTP allowed only on localhost)')
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Invalid API base URL')
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.thinking = thinking
        self.usage = {"prompt": 0, "completion": 0, "cache_hit": 0, "requests": 0}

    # ------------------------------------------------------------------
    def _payload(self, messages, tools):
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if self.thinking == "off":
            payload["thinking"] = {"type": "disabled"}
            # Most repeatable sampling. Thinking mode ignores temperature and has no seed.
            payload["temperature"] = 0
        else:
            payload["thinking"] = {"type": "enabled"}
            payload["reasoning_effort"] = self.thinking
        if tools:
            payload["tools"] = tools
        return payload

    def _open(self, payload):
        data = json.dumps(payload).encode("utf-8")
        hints = {
            401: "API key is wrong. Check DEEPSEEK_API_KEY.",
            402: "Your DeepSeek balance is empty. Top up at platform.deepseek.com.",
            422: "Bad parameters (wrong model name? try /model deepseek-flash).",
        }
        for attempt in range(3):
            req = urllib.request.Request(
                f"{self.base_url}/chat/completions",
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                    "Accept": "text/event-stream",
                },
            )
            try:
                return urllib.request.urlopen(req, timeout=90)
            except urllib.error.HTTPError as e:
                detail = e.read(600).decode("utf-8", "replace")
                if self.api_key:
                    detail = detail.replace(self.api_key, '[KEY]')
                if e.code in (429, 500, 502, 503) and attempt < 2:
                    time.sleep(3 * (attempt + 1))      # server busy: wait and retry
                    continue
                raise APIError(f"HTTP {e.code}: {hints.get(e.code, detail)}") from None
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < 2:
                    time.sleep(2)
                    continue
                raise APIError(f"Could not reach {self.base_url} ({getattr(e, 'reason', str(e))}). Check your internet.") from None
        raise APIError("Request failed after retries.")

    # ------------------------------------------------------------------
    def chat(self, messages, tools=None, on_text=None, on_reasoning=None):
        """Stream one assistant reply. Returns the full assistant message dict:
        {"role": "assistant", "content": str, "reasoning_content": str?, "tool_calls": [...]?}
        on_text / on_reasoning are called with each piece as it arrives."""
        resp = self._open(self._payload(messages, tools))
        content, reasoning, calls = [], [], {}
        finished = False
        with resp:
            for raw in resp:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue          # blank lines and ": keep-alive" comments
                data = line[5:].strip()
                if data == "[DONE]":
                    finished = True
                    break
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if chunk.get("usage"):
                    u = chunk["usage"]
                    self.usage["prompt"] += u.get("prompt_tokens", 0)
                    self.usage["completion"] += u.get("completion_tokens", 0)
                    self.usage["cache_hit"] += u.get("prompt_cache_hit_tokens", 0)
                for choice in chunk.get("choices", []):
                    if choice.get('finish_reason') in ('length', 'content_filter'):
                        raise APIError('Response truncated/filtered; partial tool calls discarded')
                    delta = choice.get("delta") or {}
                    if delta.get("reasoning_content"):
                        reasoning.append(delta["reasoning_content"])
                        if on_reasoning:
                            on_reasoning(delta["reasoning_content"])
                    if delta.get("content"):
                        content.append(delta["content"])
                        if on_text:
                            on_text(delta["content"])
                    # Tool calls arrive in pieces; glue them together by index
                    for tc in delta.get("tool_calls") or []:
                        slot = calls.setdefault(tc.get("index", 0),
                                                {"id": "", "type": "function",
                                                 "function": {"name": "", "arguments": ""}})
                        if tc.get("id"):
                            slot["id"] = tc["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["function"]["name"] += fn["name"]
                        if fn.get("arguments"):
                            slot["function"]["arguments"] += fn["arguments"]
        if not finished:
            raise APIError('Stream ended before [DONE]; partial response discarded')
        self.usage["requests"] += 1
        msg = {"role": "assistant", "content": "".join(content)}
        # DeepSeek rule: when tools are used with thinking mode, reasoning_content
        # must be sent back in later requests, so we keep it in the message.
        if reasoning:
            msg["reasoning_content"] = "".join(reasoning)
        if calls:
            msg["tool_calls"] = [calls[i] for i in sorted(calls)]
        return msg
