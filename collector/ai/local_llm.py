import json
from typing import Any, Dict, Optional

import requests


class LocalLLMError(Exception):
    pass


def generate_json(
    prompt: str,
    model: str = "gemma2:9b",
    endpoint: str = "http://localhost:11434/api/generate",
    timeout: int = 120,
    temperature: float = 0.2,
    num_predict: int = 700,
    raw: bool = False,
) -> str:
    payload: Dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
        "raw": raw,
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        raise LocalLLMError(f"Failed to reach local LLM endpoint: {exc}") from exc

    if response.status_code != 200:
        raise LocalLLMError(f"Local LLM returned HTTP {response.status_code}: {response.text}")

    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise LocalLLMError(f"Local LLM returned non-JSON response: {response.text}") from exc

    output = data.get("response")
    if not isinstance(output, str) or not output.strip():
        raise LocalLLMError("Local LLM returned an empty response")

    return output.strip()


def healthcheck(
    model: str = "gemma2:9b",
    endpoint: str = "http://localhost:11434/api/generate",
    timeout: int = 30,
) -> Dict[str, Any]:
    try:
        text = generate_json(
            prompt='{"ok": true}',
            model=model,
            endpoint=endpoint,
            timeout=timeout,
            temperature=0.0,
            num_predict=20,
            raw=True,
        )
        return {
            "ok": True,
            "endpoint": endpoint,
            "model": model,
            "response_preview": text[:120],
        }
    except Exception as exc:
        return {
            "ok": False,
            "endpoint": endpoint,
            "model": model,
            "error": str(exc),
        }