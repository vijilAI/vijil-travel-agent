import json
import os
import base64
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

# Env vars:
# UNPROTECTED_URL = http://<travel-agent-nlb>:9000/v1/chat/completions
# DOME_URL        = https://dome.dev05.vijil.ai
# DOME_API_KEY    = abc-123        (or real key)
# VIJIL_AGENT_ID  = <optional>     (UUID if you want Dome to know which agent)

UNPROTECTED_URL = os.environ["UNPROTECTED_URL"]
DOME_URL = os.environ["DOME_URL"]
DOME_API_KEY = os.environ.get("DOME_API_KEY", "abc-123")
VIJIL_AGENT_ID = os.environ.get("VIJIL_AGENT_ID")

INPUT_URL = f"{DOME_URL.rstrip('/')}/input_detection"
OUTPUT_URL = f"{DOME_URL.rstrip('/')}/output_detection"


def _get_body(event):
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body)
    return body


def _http_post(url: str, body: bytes, headers: dict) -> tuple[int, dict, str]:
    ct = headers.get("content-type", "application/json")
    req = urlrequest.Request(url, data=body, method="POST")
    req.add_header("Content-Type", ct)

    try:
        with urlrequest.urlopen(req, timeout=30) as resp:
            status = resp.getcode()
            resp_headers = dict(resp.headers.items())
            charset = resp.headers.get_content_charset() or "utf-8"
            text = resp.read().decode(charset, errors="replace")
            return status, resp_headers, text
    except HTTPError as e:
        charset = e.headers.get_content_charset() or "utf-8" if e.headers else "utf-8"
        text = e.read().decode(charset, errors="replace") if e.fp else str(e)
        return e.code, dict(e.headers.items()) if e.headers else {}, text
    except URLError as e:
        msg = f"Upstream request to {url} failed: {e}"
        return 502, {"Content-Type": "application/json"}, json.dumps({"error": msg})


def _http_get(url: str, params: dict) -> tuple[int, dict, str]:
    # Append query string
    query = urlencode(params, doseq=True)
    full_url = f"{url}?{query}"
    req = urlrequest.Request(full_url, method="GET")

    try:
        with urlrequest.urlopen(req, timeout=30) as resp:
            status = resp.getcode()
            resp_headers = dict(resp.headers.items())
            charset = resp.headers.get_content_charset() or "utf-8"
            text = resp.read().decode(charset, errors="replace")
            return status, resp_headers, text
    except HTTPError as e:
        charset = e.headers.get_content_charset() or "utf-8" if e.headers else "utf-8"
        text = e.read().decode(charset, errors="replace") if e.fp else str(e)
        return e.code, dict(e.headers.items()) if e.headers else {}, text
    except URLError as e:
        msg = f"Upstream request to {url} failed: {e}"
        return 502, {"Content-Type": "application/json"}, json.dumps({"error": msg})


def _extract_user_input(chat_request: dict) -> str:
    # OpenAI chat schema: messages is a list; take last user message content
    messages = chat_request.get("messages") or []
    if not messages:
        return ""
    last = messages[-1]
    return last.get("content", "")


def _extract_agent_outputs(agent_payload: dict) -> list[str]:
    # Collect message.content from all choices
    outputs: list[str] = []
    for choice in agent_payload.get("choices", []):
        msg = choice.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            outputs.append(content)
    return outputs


def _set_agent_outputs(agent_payload: dict, new_contents: list[str], finish_reason: str | None = None) -> dict:
    choices = agent_payload.get("choices", [])
    for idx, (choice, new_text) in enumerate(zip(choices, new_contents)):
        msg = choice.get("message") or {}
        msg["content"] = new_text
        choice["message"] = msg
        if finish_reason:
            choice["finish_reason"] = finish_reason
        choices[idx] = choice
    agent_payload["choices"] = choices
    return agent_payload


def lambda_handler(event, context):
    path = event.get("rawPath") or event.get("path", "")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    raw_body = _get_body(event)

    # 1) Unprotected: straight to the travel agent
    # Support both /travel-agent/unprotected and /travel-agent/unprotected/v1/chat/completions
    if "/travel-agent/unprotected" in path:
        status, resp_headers, text = _http_post(
            UNPROTECTED_URL,
            raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body,
            headers,
        )
        return {
            "statusCode": status,
            "headers": {"Content-Type": resp_headers.get("Content-Type", "application/json")},
            "body": text,
        }

    # 2) Protected: Dome input_detection -> agent -> Dome output_detection
    # Support both /travel-agent/protected and /travel-agent/protected/v1/chat/completions
    if "/travel-agent/protected" in path:
        # Parse incoming chat request JSON
        try:
            chat_request = json.loads(raw_body or "{}")
        except json.JSONDecodeError:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Invalid JSON in request body"}),
            }

        user_text = _extract_user_input(chat_request) or ""

        # --- Dome input_detection (input gate, via GET) ---
        input_params = {
            "api_key": DOME_API_KEY,
            "input_str": user_text,
        }
        if VIJIL_AGENT_ID:
            input_params["agent_id"] = VIJIL_AGENT_ID

        pre_status, _, pre_text = _http_get(INPUT_URL, input_params)
        if pre_status >= 400:
            return {
                "statusCode": pre_status,
                "headers": {"Content-Type": "application/json"},
                "body": pre_text,
            }
        pre_payload = json.loads(pre_text or "{}")

        # Expected: { "flagged": bool, "response": str }
        if pre_payload.get("flagged"):
            guard_msg = pre_payload.get(
                "response",
                "I'm sorry, but as per Vijil Dome, this request violates my operating policies, and I cannot respond to it.",
            )
            # Return a minimal OpenAI-style completion
            blocked = {
                "id": "chatcmpl-dome-input-blocked",
                "object": "chat.completion",
                "created": 0,
                "model": chat_request.get("model", "llama-3.1-8b-instant"),
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": guard_msg},
                    "finish_reason": "inputGuardrail",
                }],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            }
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(blocked),
            }

        # --- Call unprotected agent (EKS travel agent) ---
        agent_status, _, agent_text = _http_post(
            UNPROTECTED_URL,
            json.dumps(chat_request).encode("utf-8"),
            {"content-type": "application/json"},
        )
        if agent_status >= 400:
            return {
                "statusCode": agent_status,
                "headers": {"Content-Type": "application/json"},
                "body": agent_text,
            }
        agent_payload = json.loads(agent_text or "{}")

        # Collect agent outputs
        agent_outputs = _extract_agent_outputs(agent_payload)
        if not agent_outputs:
            # Nothing to scan; just return as-is
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(agent_payload),
            }

        # --- Dome output_detection for each message ---
        new_contents: list[str] = []
        flagged_output = False
        for msg in agent_outputs:
            out_params = {
                "api_key": DOME_API_KEY,
                "output_str": msg,
            }
            if VIJIL_AGENT_ID:
                out_params["agent_id"] = VIJIL_AGENT_ID

            out_status, _, out_text = _http_get(OUTPUT_URL, out_params)
            if out_status >= 400:
                # On detector error, fall back to original response
                new_contents.append(msg)
                continue
            out_payload = json.loads(out_text or "{}")
            safe = out_payload.get("response", msg)
            new_contents.append(safe)

            if out_payload.get("flagged"):
                # Replace entire response with guardrail message and stop
                guard_msg = "I'm sorry, but as per Vijil Dome, the generated response violated my operating policies. I cannot provide this response."
                agent_payload = _set_agent_outputs(
                    agent_payload,
                    [guard_msg],
                    finish_reason="outputGuardrail",
                )
                flagged_output = True
                break

        if not flagged_output:
            agent_payload = _set_agent_outputs(agent_payload, new_contents)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(agent_payload),
        }

    return {
        "statusCode": 404,
        "body": json.dumps({"error": f"Unknown path {path}"}),
    }