---
sidebar_position: 3
---

# AI RCA Redacting Proxy

Use this local OpenAI-compatible proxy when you need to inspect Coroot AI RCA request shape without exposing API keys, license keys, or full prompts in logs.

The proxy supports:

* `GET /v1/models`
* `POST /v1/chat/completions`
* dry-run mode that returns a deterministic RCA JSON response
* forwarding mode to an upstream OpenAI-compatible API
* JSONL request logs with redacted excerpts, message sizes, section hashes, model names, and response metadata

## Start In Dry-Run Mode

```bash
AI_PROXY_DRY_RUN=1 \
AI_PROXY_CLIENT_TOKEN=coroot-proxy-token \
AI_PROXY_LOG_FILE=/tmp/coroot-ai-rca-proxy.jsonl \
python3 hack/ai-redacting-proxy.py --listen 0.0.0.0:18081
```

Configure Coroot as an OpenAI-compatible API:

* Base URL: `http://host.docker.internal:18081/v1`
* API key: `coroot-proxy-token`
* Model: `gpt-5.5`

Dry-run mode does not call an external model. It is useful for capturing the RCA evidence package that Coroot would send to the model.

## Forward To OpenAI

Store the upstream key in a local file:

```bash
printf '%s' "$OPENAI_API_KEY" > /tmp/openai.key
chmod 600 /tmp/openai.key
```

Run the proxy in forwarding mode:

```bash
AI_PROXY_DRY_RUN=0 \
AI_PROXY_UPSTREAM_API_KEY_FILE=/tmp/openai.key \
AI_PROXY_UPSTREAM_BASE_URL=https://api.openai.com/v1 \
AI_PROXY_CLIENT_TOKEN=coroot-proxy-token \
AI_PROXY_LOG_FILE=/tmp/coroot-ai-rca-proxy.jsonl \
python3 hack/ai-redacting-proxy.py --listen 0.0.0.0:18081
```

Coroot still uses the same OpenAI-compatible settings:

* Base URL: `http://host.docker.internal:18081/v1`
* API key: `coroot-proxy-token`
* Model: `gpt-5.5`

The upstream OpenAI key stays outside Coroot and is never returned to the browser.

## Inspect Logs

```bash
tail -n 20 /tmp/coroot-ai-rca-proxy.jsonl | jq .
```

Each log event includes message roles, character counts, SHA-256 hashes, redacted excerpts, and detected RCA sections such as candidates, propagation map findings, widgets, evidence registry, traces, logs, Kubernetes events, and remediation constraints.

## Official AI RCA Request Contract

A local Enterprise trial capture showed that incident RCA uses OpenAI Chat Completions with tool calling:

* request keys: `model`, `messages`, `tools`, `tool_choice`, `max_completion_tokens`
* default completion budget observed during RCA: `max_completion_tokens=8000`
* forced tool choice: function `record_summary`
* required tool arguments: `short_summary`, `root_cause`, `immediate_fixes`, `detailed_root_cause_analysis`
* message shape: one system message with RCA rules and one user message with metric anomalies, related findings, and related logs

Dry-run mode returns a compatible `tool_calls` response when the request includes tools. This lets the official RCA pipeline complete without calling an external model.

For secondary development, keep the same contract for parity:

* build deterministic evidence first
* pass only grounded metrics, logs, traces, Kubernetes events, and dependency findings to the model
* force structured output through a tool/function schema
* validate required fields before writing `incident.rca`
* fall back to built-in RCA when no model is configured or the provider fails

## Boundaries

This proxy does not remove or bypass Coroot Enterprise licensing. Use a valid Coroot Enterprise license for official EE behavior analysis. For the secondary-developed Community Edition path, built-in RCA and optional AI rendering can run without an Enterprise license.
