# gemini_client.py

import os
import requests
import json
from typing import Dict, Any, Optional

# --- Config from environment -------------------------------------------------
API_KEY = os.getenv("AIzaSyCGoWNw0C3WJCO4FiSHx7mZh2tEfHSC77U")
MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
DEFAULT_BASE = "https://generativelanguage.googleapis.com/v1beta"
API_URL = os.getenv("GEMINI_API_URL", f"{DEFAULT_BASE}/models/{MODEL}:generateContent")

if not API_KEY:
    # Raise here so callers know immediately it's not configured
    raise RuntimeError("GOOGLE_API_KEY is not set. Please export it into the environment.")

HEADERS = {
    "Content-Type": "application/json",
    # API-key usage: Bearer or key param may be needed depending on how the key is issued.
    # For simple API-key-in-header approach we use Bearer. If your key type needs ?key=..., update below.
    "Authorization": f"Bearer {API_KEY}"
}


def _extract_text_from_response(resp_json: Dict[str, Any]) -> str:
    """
    Try to extract human-readable text from the provider response.
    Different endpoint/model shapes may return different fields; handle common cases:
      - 'candidates' (list) with 'content' keys
      - nested 'output' or 'content' fields
      - fallback to dumping entire JSON
    """
    # common pattern: candidates -> content
    if isinstance(resp_json, dict):
        if "candidates" in resp_json and isinstance(resp_json["candidates"], list):
            pieces = []
            for c in resp_json["candidates"]:
                if isinstance(c, dict):
                    # some responses use 'content' or 'text'
                    pieces.append(c.get("content") or c.get("text") or "")
            return "\n".join(p for p in pieces if p)
        # another common place
        if "output" in resp_json and isinstance(resp_json["output"], str):
            return resp_json["output"]
        if "content" in resp_json and isinstance(resp_json["content"], str):
            return resp_json["content"]
        # older/different shapes
        if "generations" in resp_json and isinstance(resp_json["generations"], list):
            return " ".join(g.get("text", "") for g in resp_json["generations"])
    # fallback: pretty-print JSON
    return json.dumps(resp_json, indent=2)


def ask_gemini(prompt: str, max_output_tokens: int = 300, temperature: Optional[float] = None) -> Dict[str, Any]:
    """
    Call Gemini-like `generateContent` REST endpoint and return a dict:
      {
        "ok": True/False,
        "status_code": int,
        "raw": <full json response or text>,
        "text": <extracted text (if any)>,
        "error": <error string if any>
      }

    Note: Adjust request body to match exact model/endpoint requirements if your account expects
    a different request schema (chat-style, JSON-mode, etc.).
    """
    body = {
        "model": MODEL,
        # Simple text mode; some endpoints accept 'text' or 'input' or 'messages' - adapt if needed.
        "text": {"instruction": prompt},
        "maxOutputTokens": int(max_output_tokens)
    }
    if temperature is not None:
        # not all endpoints accept temperature in this exact place; remove if your endpoint rejects it
        body["temperature"] = float(temperature)

    try:
        resp = requests.post(API_URL, headers=HEADERS, json=body, timeout=20)
    except requests.RequestException as e:
        return {"ok": False, "error": f"request failed: {e}"}

    result = {"ok": resp.status_code == 200, "status_code": resp.status_code}
    try:
        payload = resp.json()
        result["raw"] = payload
        result["text"] = _extract_text_from_response(payload)
        if resp.status_code != 200:
            # include server error body
            result["error"] = result.get("text") or str(payload)
    except ValueError:
        # non-json body
        result["raw"] = resp.text
        result["text"] = resp.text
        if resp.status_code != 200:
            result["error"] = resp.text

    return result


# Simple CLI demo
if __name__ == "__main__":
    demo_prompt = (
        "You are a security analyst. Given this alert summary: "
        "Multiple unique ports contacted quickly from 203.0.113.5 — suggest 3 prioritized triage steps "
        "and a one-sentence justification for each."
    )
    out = ask_gemini(demo_prompt, max_output_tokens=250)
    print("Status:", out["status_code"])
    if out.get("ok"):
        print("--- Extracted text ---\n")
        print(out["text"])
    else:
        print("--- Error / Raw response ---\n")
        print(out.get("error") or out.get("raw"))
