#!/usr/bin/env python3
"""OpenAI-compatible redacting proxy for Coroot AI RCA analysis.

The proxy is intentionally small and dependency-free. It records request shape,
model, message sizes, hashes, and redacted excerpts, then either forwards the
request to an upstream OpenAI-compatible API or returns a deterministic dry-run
response.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


DEFAULT_LISTEN = "127.0.0.1:18081"
DEFAULT_UPSTREAM = "https://api.openai.com/v1"
DEFAULT_LOG = "/tmp/coroot-ai-rca-proxy.jsonl"

SECRET_PATTERNS = [
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer <redacted>"),
    (re.compile(r"sk-ant-[A-Za-z0-9._-]{8,}"), "sk-ant-<redacted>"),
    (re.compile(r"sk-[A-Za-z0-9._-]{8,}"), "sk-<redacted>"),
    (re.compile(r"COROOT-[A-Za-z0-9-]{12,}"), "COROOT-<redacted>"),
    (
        re.compile(r'(?i)("?(?:api[_-]?key|authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|secret|password|license)"?\s*[:=]\s*")[^"]+(")'),
        r"\1<redacted>\2",
    ),
    (
        re.compile(r"(?i)((?:api[_-]?key|authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|secret|password|license)\s*[:=]\s*)\S+"),
        r"\1<redacted>",
    ),
]

SENSITIVE_KEY = re.compile(r"(?i)^(api[_-]?key|authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|secret|password|license)$")

SECTION_MARKERS = [
    "Built-in anomaly summary:",
    "Built-in root-cause conclusion:",
    "Built-in remediation hint:",
    "Candidates:",
    "Propagation map findings:",
    "Relevant chart/widget findings:",
    "Evidence registry:",
    "Investigation trajectory:",
    "Missing evidence:",
    "Historical RCA context:",
    "Constraints:",
    "Problem:",
    "Summary:",
    "Correlation:",
    "Metrics:",
    "Related logs:",
    "Related traces:",
    "Kubernetes events:",
]


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def read_secret(name: str) -> str:
    direct = os.getenv(name, "")
    if direct:
        return direct
    path = os.getenv(name + "_FILE", "")
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8").strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def redact(value: Any) -> Any:
    if isinstance(value, str):
        text = value
        for pattern, repl in SECRET_PATTERNS:
            text = pattern.sub(repl, text)
        return text
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            if SENSITIVE_KEY.search(str(key)):
                out[key] = "<redacted>"
            else:
                out[key] = redact(val)
        return out
    return value


def compact_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item.get("content"), str):
                    parts.append(item["content"])
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def excerpt(text: str, limit: int) -> str:
    text = " ".join(redact(text).split())
    if len(text) <= limit:
        return text
    return text[:limit] + "...<truncated>"


def split_sections(text: str, excerpt_limit: int) -> list[dict[str, Any]]:
    markers: list[tuple[int, str]] = []
    for marker in SECTION_MARKERS:
        idx = text.find(marker)
        if idx >= 0:
            markers.append((idx, marker.rstrip(":")))
    for match in re.finditer(r"(?m)^(#{1,4})\s+(.{2,80})\s*$", text):
        markers.append((match.start(), match.group(2).strip()))
    for match in re.finditer(r"(?m)^([A-Z][A-Za-z0-9 /_.-]{2,80}):\s*$", text):
        markers.append((match.start(), match.group(1).strip()))

    seen = set()
    ordered = []
    for idx, name in sorted(markers):
        key = (idx, name)
        if key not in seen:
            seen.add(key)
            ordered.append((idx, name))

    sections = []
    for pos, (idx, name) in enumerate(ordered):
        end = ordered[pos + 1][0] if pos + 1 < len(ordered) else len(text)
        body = text[idx:end]
        sections.append(
            {
                "name": name,
                "chars": len(body),
                "sha256": sha256_text(body),
                "excerpt": excerpt(body, excerpt_limit),
            }
        )
    return sections


def summarize_messages(messages: Any, excerpt_limit: int) -> list[dict[str, Any]]:
    if not isinstance(messages, list):
        return []
    result = []
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue
        text = compact_text(msg.get("content", ""))
        result.append(
            {
                "index": i,
                "role": msg.get("role", ""),
                "chars": len(text),
                "sha256": sha256_text(text),
                "excerpt": excerpt(text, excerpt_limit),
                "sections": split_sections(text, excerpt_limit),
            }
        )
    return result


def summarize_tools(tools: Any, excerpt_limit: int) -> list[dict[str, Any]]:
    if not isinstance(tools, list):
        return []
    result = []
    for i, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        function = tool.get("function") if isinstance(tool.get("function"), dict) else {}
        parameters = function.get("parameters") if isinstance(function.get("parameters"), dict) else {}
        properties = parameters.get("properties") if isinstance(parameters.get("properties"), dict) else {}
        result.append(
            {
                "index": i,
                "type": tool.get("type"),
                "name": function.get("name"),
                "description": excerpt(str(function.get("description", "")), excerpt_limit),
                "property_names": sorted(str(k) for k in properties.keys()),
                "required": parameters.get("required") if isinstance(parameters.get("required"), list) else [],
            }
        )
    return result


def schema_default(name: str, schema: Any) -> Any:
    known = {
        "status": "OK",
        "error": "",
        "short_summary": "Dry-run RCA capture completed; the redacted request was logged by the local proxy.",
        "root_cause": "The proxy did not call an external model. Use the captured Coroot evidence to inspect the RCA request structure.",
        "immediate_fixes": "Review the proxy JSONL log, then rerun with forwarding enabled when ready.",
        "detailed_root_cause_analysis": (
            "## Incident Overview\n"
            "The local redacting proxy captured the AI RCA request shape in dry-run mode.\n\n"
            "## Cascading Impact\n"
            "No external model inference was performed. Review the JSONL log for propagation map, candidates, widgets, traces, logs, and events.\n\n"
            "## Trace Evidence\n"
            "Evidence excerpts were redacted and hashed so they can be compared without exposing secrets.\n\n"
            "## Remediation\n"
            "Run the proxy in forwarding mode after validating the captured request."
        ),
        "confidence": "low",
        "missing_evidence": ["external model inference skipped by dry-run proxy"],
        "propagation_map": {"applications": []},
        "widgets": [],
    }
    if name in known:
        return known[name]
    if not isinstance(schema, dict):
        return ""
    typ = schema.get("type")
    if isinstance(typ, list):
        typ = next((t for t in typ if t != "null"), typ[0] if typ else "string")
    if typ == "object":
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        required = schema.get("required") if isinstance(schema.get("required"), list) else list(props.keys())
        return {key: schema_default(str(key), props.get(key, {})) for key in required}
    if typ == "array":
        return []
    if typ == "number":
        return 0
    if typ == "integer":
        return 0
    if typ == "boolean":
        return False
    return ""


def dry_run_tool_arguments(body: dict[str, Any]) -> tuple[str, str] | None:
    tools = body.get("tools")
    if not isinstance(tools, list) or not tools:
        return None
    first = tools[0]
    if not isinstance(first, dict):
        return None
    function = first.get("function")
    if not isinstance(function, dict):
        return None
    name = function.get("name")
    if not isinstance(name, str) or not name:
        return None
    parameters = function.get("parameters") if isinstance(function.get("parameters"), dict) else {}
    properties = parameters.get("properties") if isinstance(parameters.get("properties"), dict) else {}
    required = parameters.get("required") if isinstance(parameters.get("required"), list) else list(properties.keys())
    args = {key: schema_default(str(key), properties.get(key, {})) for key in required}
    if not args:
        args = {
            "short_summary": schema_default("short_summary", {}),
            "root_cause": schema_default("root_cause", {}),
            "immediate_fixes": schema_default("immediate_fixes", {}),
            "detailed_root_cause_analysis": schema_default("detailed_root_cause_analysis", {}),
        }
    return name, json.dumps(args, ensure_ascii=False)


class ProxyConfig:
    def __init__(self) -> None:
        self.upstream_base_url = os.getenv("AI_PROXY_UPSTREAM_BASE_URL", DEFAULT_UPSTREAM).rstrip("/")
        self.upstream_api_key = read_secret("AI_PROXY_UPSTREAM_API_KEY") or read_secret("OPENAI_API_KEY")
        self.client_token = read_secret("AI_PROXY_CLIENT_TOKEN")
        self.log_file = os.getenv("AI_PROXY_LOG_FILE", DEFAULT_LOG)
        self.dry_run = env_bool("AI_PROXY_DRY_RUN", not bool(self.upstream_api_key))
        self.excerpt_chars = int(os.getenv("AI_PROXY_EXCERPT_CHARS", "800"))
        self.request_timeout = float(os.getenv("AI_PROXY_TIMEOUT_SECONDS", "120"))


CFG = ProxyConfig()


def write_log(event: dict[str, Any]) -> None:
    event = redact(event)
    event["ts"] = int(time.time())
    path = Path(CFG.log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def normalize_endpoint(path: str) -> str:
    path = path.split("?", 1)[0]
    if path.startswith("/v1/"):
        path = path[3:]
    return path


def dry_run_completion(body: dict[str, Any]) -> bytes:
    model = body.get("model") or "gpt-5.5"
    content = {
        "short_summary": "Dry-run RCA capture completed; the redacted request was logged by the local proxy.",
        "root_cause": "The proxy did not call an external model. Use the captured Coroot evidence to inspect the RCA request structure.",
        "detailed_root_cause_analysis": (
            "## Incident Overview\n"
            "The local redacting proxy captured the AI RCA request shape in dry-run mode.\n\n"
            "## Cascading Impact\n"
            "No external model inference was performed. Review the JSONL log for propagation map, candidates, widgets, traces, logs, and events.\n\n"
            "## Trace Evidence\n"
            "Evidence excerpts were redacted and hashed so they can be compared without exposing secrets.\n\n"
            "## Remediation\n"
            "Run the proxy in forwarding mode after validating the captured request."
        ),
        "immediate_fixes": "Review the proxy JSONL log, then rerun with AI_PROXY_DRY_RUN=0 and an upstream API key when ready.",
        "confidence": "low",
        "missing_evidence": ["external model inference skipped by dry-run proxy"],
    }
    message: dict[str, Any] = {"role": "assistant", "content": json.dumps(content, ensure_ascii=False)}
    finish_reason = "stop"
    tool_call = dry_run_tool_arguments(body)
    if tool_call:
        name, arguments = tool_call
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_coroot_proxy_dry_run",
                    "type": "function",
                    "function": {"name": name, "arguments": arguments},
                }
            ],
        }
        finish_reason = "tool_calls"
    payload = {
        "id": "chatcmpl-coroot-proxy-dry-run",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": finish_reason,
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
    return json.dumps(payload).encode("utf-8")


def dry_run_models() -> bytes:
    payload = {
        "object": "list",
        "data": [
            {"id": "gpt-5.5", "object": "model", "created": int(time.time()), "owned_by": "proxy-dry-run"},
            {"id": "claude-opus-4-6", "object": "model", "created": int(time.time()), "owned_by": "proxy-dry-run"},
        ],
    }
    return json.dumps(payload).encode("utf-8")


def provider_error(status: int, message: str) -> bytes:
    return json.dumps({"error": {"message": message, "type": "proxy_error", "code": status}}).encode("utf-8")


def forward(endpoint: str, method: str, body: bytes | None) -> tuple[int, dict[str, str], bytes]:
    if not CFG.upstream_api_key:
        return 401, {"Content-Type": "application/json"}, provider_error(401, "upstream API key is not configured")
    url = CFG.upstream_base_url + endpoint
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", "Bearer " + CFG.upstream_api_key)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=CFG.request_timeout) as resp:
            headers = {"Content-Type": resp.headers.get("Content-Type", "application/json")}
            return resp.status, headers, resp.read()
    except urllib.error.HTTPError as e:
        data = e.read()
        headers = {"Content-Type": e.headers.get("Content-Type", "application/json")}
        return e.code, headers, data
    except Exception as e:  # noqa: BLE001 - keep proxy dependency-free and robust.
        return 502, {"Content-Type": "application/json"}, provider_error(502, str(e))


class Handler(BaseHTTPRequestHandler):
    server_version = "CorootAIRedactingProxy/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def _send(self, status: int, data: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {"Content-Type": "application/json"}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        if not CFG.client_token:
            return True
        return self.headers.get("Authorization", "") == "Bearer " + CFG.client_token

    def _body(self) -> bytes:
        size = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(size) if size else b""

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        endpoint = normalize_endpoint(self.path)
        if endpoint == "/healthz":
            self._send(200, b'{"status":"ok"}')
            return
        if endpoint != "/models":
            self._send(404, provider_error(404, "unsupported endpoint"))
            return
        if not self._authorized():
            self._send(401, provider_error(401, "unauthorized"))
            return
        write_log({"type": "models", "path": self.path, "dry_run": CFG.dry_run, "client_auth": bool(self.headers.get("Authorization"))})
        if CFG.dry_run:
            self._send(200, dry_run_models())
            return
        status, headers, data = forward("/models", "GET", None)
        write_log({"type": "models_response", "status": status, "bytes": len(data), "sha256": sha256_text(data.decode("utf-8", "replace"))})
        self._send(status, data, headers)

    def do_POST(self) -> None:  # noqa: N802
        endpoint = normalize_endpoint(self.path)
        if endpoint != "/chat/completions":
            self._send(404, provider_error(404, "unsupported endpoint"))
            return
        if not self._authorized():
            self._send(401, provider_error(401, "unauthorized"))
            return
        raw = self._body()
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            self._send(400, provider_error(400, "invalid JSON: " + str(e)))
            return
        messages = summarize_messages(body.get("messages"), CFG.excerpt_chars)
        tools = summarize_tools(body.get("tools"), CFG.excerpt_chars)
        write_log(
            {
                "type": "chat_completion",
                "path": self.path,
                "dry_run": CFG.dry_run,
                "body_keys": sorted(str(k) for k in body.keys()),
                "model": body.get("model"),
                "temperature": body.get("temperature"),
                "max_tokens": body.get("max_tokens"),
                "max_completion_tokens": body.get("max_completion_tokens"),
                "tool_choice": body.get("tool_choice"),
                "tool_count": len(tools),
                "tools": tools,
                "body_sha256": sha256_text(raw.decode("utf-8", "replace")),
                "message_count": len(messages),
                "messages": messages,
            }
        )
        if CFG.dry_run:
            data = dry_run_completion(body)
            write_log({"type": "chat_completion_response", "status": 200, "dry_run": True, "bytes": len(data)})
            self._send(200, data)
            return
        status, headers, data = forward("/chat/completions", "POST", raw)
        response_event = {"type": "chat_completion_response", "status": status, "bytes": len(data), "sha256": sha256_text(data.decode("utf-8", "replace"))}
        if status >= 400:
            response_event["error_excerpt"] = excerpt(data.decode("utf-8", "replace"), CFG.excerpt_chars)
        else:
            try:
                parsed = json.loads(data.decode("utf-8"))
                response_event["model"] = parsed.get("model")
                response_event["choices"] = len(parsed.get("choices", []))
            except Exception:
                response_event["parse"] = "non_json_response"
        write_log(response_event)
        self._send(status, data, headers)


def parse_listen(value: str) -> tuple[str, int]:
    if ":" not in value:
        raise ValueError("--listen must be host:port")
    host, port = value.rsplit(":", 1)
    return host, int(port)


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenAI-compatible redacting proxy for Coroot AI RCA")
    parser.add_argument("--listen", default=DEFAULT_LISTEN, help=f"listen address, default {DEFAULT_LISTEN}")
    args = parser.parse_args()
    host, port = parse_listen(args.listen)
    if host in {"0.0.0.0", "::"} and not CFG.client_token:
        print("warning: binding a public interface without AI_PROXY_CLIENT_TOKEN", file=sys.stderr)
    print(
        json.dumps(
            {
                "listen": args.listen,
                "dry_run": CFG.dry_run,
                "upstream_base_url": CFG.upstream_base_url,
                "upstream_api_key": "<configured>" if CFG.upstream_api_key else "<missing>",
                "client_token": "<configured>" if CFG.client_token else "<not-required>",
                "log_file": CFG.log_file,
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    server = ThreadingHTTPServer((host, port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
