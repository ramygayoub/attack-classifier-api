"""
Attack Classification API
---------------------------
Standalone REST API version of the honeypot's hybrid rule-based + LLM
classification engine. Accepts raw session event data, returns a
structured classification.

Endpoints:
    POST /classify   - classify a session's events
    GET  /health      - Kubernetes liveness/readiness probe target
    GET  /metrics     - Prometheus-scrapeable metrics
"""

import json
import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response
from google import genai
from google.genai import errors as genai_errors

app = FastAPI(title="Attack Classification API", version="1.0.0")

GEMINI_MODEL = "gemini-3.1-flash-lite"
_client: genai.Client | None = None

# ---- Prometheus metrics ----
CLASSIFICATION_COUNT = Counter(
    "classifications_total", "Total classification requests", ["method", "attack_type"]
)
CLASSIFICATION_LATENCY = Histogram(
    "classification_duration_seconds", "Time spent classifying a session"
)
LLM_CALL_COUNT = Counter(
    "llm_calls_total", "Total calls made to the LLM (vs. rule-based)"
)

CLASSIFICATION_PROMPT = """You are a security analyst reviewing a honeypot session log. \
Based on the sequence of events below, classify the attacker's likely behavior.

Respond with ONLY a JSON object, no other text, in this exact format:
{{
  "attack_type": "one of: port_scan, credential_stuffing, brute_force, exploit_attempt, \
recon, malware_download, botnet_recruitment, unknown",
  "confidence": "high|medium|low",
  "summary": "one sentence plain-English summary",
  "notable_commands": ["list", "of", "suspicious", "commands"]
}}

Session events:
{events}
"""


class SessionEvents(BaseModel):
    session_id: str
    events: list[dict[str, Any]]


class ClassificationResult(BaseModel):
    session_id: str
    attack_type: str
    confidence: str
    summary: str
    notable_commands: list[str]
    classified_by: str


def get_client() -> genai.Client:
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY environment variable not set")
        _client = genai.Client(api_key=api_key)
    return _client


def rule_based_classify(events: list[dict]) -> dict | None:
    """Classify obvious cases locally, for free. Returns None if it needs the LLM."""
    event_ids = [e.get("eventid", "") for e in events]

    has_login_success = "cowrie.login.success" in event_ids
    has_login_failed = "cowrie.login.failed" in event_ids
    has_commands = "cowrie.command.input" in event_ids

    if has_login_success and has_commands:
        return None  # send to LLM - genuinely interesting case

    if not has_login_success and not has_login_failed:
        return {
            "attack_type": "port_scan",
            "confidence": "medium",
            "summary": "Connection with no login attempt (rule-based).",
            "notable_commands": [],
        }

    if has_login_failed and not has_login_success:
        return {
            "attack_type": "brute_force",
            "confidence": "medium",
            "summary": "Failed login attempt(s), no successful authentication (rule-based).",
            "notable_commands": [],
        }

    if has_login_success and not has_commands:
        return {
            "attack_type": "credential_stuffing",
            "confidence": "medium",
            "summary": "Successful login with no follow-up commands (rule-based).",
            "notable_commands": [],
        }

    return None


def llm_classify(events: list[dict]) -> dict:
    client = get_client()
    events_text = json.dumps(events, indent=2, default=str)[:6000]

    LLM_CALL_COUNT.inc()

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=CLASSIFICATION_PROMPT.format(events=events_text),
            config={
                "response_mime_type": "application/json",
                "max_output_tokens": 2048,
                "thinking_config": {"thinking_level": "minimal"},
            },
        )
    except genai_errors.ClientError as e:
        raise HTTPException(status_code=502, detail=f"LLM classification failed: {e}")

    raw_text = response.text.strip() if response.text else ""
    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]
        raw_text = raw_text.strip()

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return {
            "attack_type": "unknown",
            "confidence": "low",
            "summary": "Could not parse LLM classification.",
            "notable_commands": [],
        }


@app.post("/classify", response_model=ClassificationResult)
def classify(payload: SessionEvents):
    start = time.time()

    result = rule_based_classify(payload.events)
    classified_by = "rule-based"

    if result is None:
        result = llm_classify(payload.events)
        classified_by = "gemini"

    CLASSIFICATION_LATENCY.observe(time.time() - start)
    CLASSIFICATION_COUNT.labels(method=classified_by, attack_type=result.get("attack_type", "unknown")).inc()

    return ClassificationResult(
        session_id=payload.session_id,
        attack_type=result.get("attack_type", "unknown"),
        confidence=result.get("confidence", "low"),
        summary=result.get("summary", ""),
        notable_commands=result.get("notable_commands", []),
        classified_by=classified_by,
    )


@app.get("/health")
def health():
    """Kubernetes liveness/readiness probe target."""
    return {"status": "ok"}


@app.get("/metrics")
def metrics():
    """Prometheus scrape endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
