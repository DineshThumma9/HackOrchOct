"""Does the request text actually authorise deletion?"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

NON_DELETION_PATTERNS = [
    r"\b(access|copy of|send me a copy|download|rectif|correct it|update my|change (the|my) email)\b",
    r"\b(unsubscribe|opt[- ]?out|marketing preferences|marketing lists only|promotional emails|stop sending)\b",
    r"\b(invoice|refund|complaint|question about|where is my order|status of my order)\b",
    r"\b(reset|resetting|password|login|misspelled|replace it|continue using)\b",
]

# Refusals and retentions dominate even when the text quotes the word
# "deletion" (for example "I am not asking for deletion").
RETENTION_PATTERNS = [
    r"not asking for deletion",
    r"not a request to (erase|delete)",
    r"not to erase",
    r"do not (delete|close|remove)",
    r"don't (delete|close|remove)",
    r"please don't delete",
    r"without (removing|deleting)",
    r"leave (the|my) (account|profile)",
    r"keep (the|my) account",
    r"keep the account as it is",
    r"retain my data",
    r"still (need|want) the account",
]

DELETION_PATTERNS = [
    r"\b(delet|eras|remov|clos|terminat|destroy)",
    r"(löschen|loeschen|supprimer|suppression|eliminar|eliminación|borrar|cancellare|削除|삭제|verwijder|excluir|exclusão|exclusao|apagar|删除)",
    r"(datenschutz|dsgvo|gdpr|rgpd|privacy request|right to be forgotten)",
]

# Deletion directed at the subject's own account or records.
EXPLICIT_DELETION_PATTERNS = [
    r"(delet|eras|remov|clos|exclus|elimin|supprim)[a-zà-ÿ]{0,20}.{0,40}(account|profile|data|record|cuenta|conta|compte|datos|dados)",
    r"(account|profile|data|record|cuenta|conta|compte|datos|dados).{0,40}(delet|eras|remov|clos|exclus|elimin|supprim)",
    r"\b(profile|account|data)\b.{0,30}\b(gone|deleted|removed)\b",
    r"\b(gone|deleted|removed)\b.{0,30}\b(profile|account)\b",
]

TEV_QUESTIONS = {
    "intent": {
        "type": "choice",
        "instructions": "What is the sender asking for?",
        "criteria": {
            "deletion": "Delete or erase the account or personal data",
            "access": "Provide a copy of the data",
            "correction": "Correct or update account details",
            "marketing_opt_out": "Stop marketing messages only",
            "login_support": "Help with login, password, or access",
            "other": "Anything else",
        },
    },
    "authorizes_deletion": {
        "type": "noul",
        "instructions": "Does this message authorize deletion of the account or personal data?",
    },
}

_CACHE_FILE = Path(__file__).resolve().parent / "data" / "tev_cache.json"
_TEV_CACHE: dict[str, dict] = {}
if _CACHE_FILE.exists():
    try:
        _TEV_CACHE = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        _TEV_CACHE = {}

_TEV_COUNTER = 0
_TEV_AVAILABLE: bool | None = None


def is_tev_service_available(url: str = "http://localhost:11434", timeout: float = 0.5) -> bool:
    """Quick probe to check if Ollama is active on localhost."""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def check_tev_available() -> bool:
    """Cached probe for Ollama availability."""
    global _TEV_AVAILABLE
    if _TEV_AVAILABLE is None:
        _TEV_AVAILABLE = is_tev_service_available()
    return _TEV_AVAILABLE


def set_tev_available(available: bool | None) -> None:
    """Explicitly override or reset Tev availability status."""
    global _TEV_AVAILABLE
    _TEV_AVAILABLE = available


def _save_cache() -> None:
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(_TEV_CACHE, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def request_authorizes_deletion_regex(text: str) -> bool:
    """Deterministic, zero-dependency pattern matching."""
    lowered = (text or "").lower()
    if not lowered.strip():
        return False
    if any(re.search(pattern, lowered) for pattern in RETENTION_PATTERNS):
        return False
    if any(re.search(pattern, lowered) for pattern in EXPLICIT_DELETION_PATTERNS):
        return True
    if any(re.search(pattern, lowered) for pattern in NON_DELETION_PATTERNS):
        return False
    return any(re.search(pattern, lowered) for pattern in DELETION_PATTERNS)


def classify_intent_tev(
    text: str,
    model: str = "tev1:4b",
    url: str = "http://localhost:11434/v1/systemone",
    timeout: float = 15.0,
) -> dict | None:
    """Classify request intent using local Tev / System One model via Ollama with exact-string caching."""
    global _TEV_COUNTER
    lowered = (text or "").strip()
    if not lowered:
        return {"intent": "other", "confidence": 1.0, "authorizes_deletion": 0.0, "authorizes": False}

    # Cache hit: instant return without computing on Ollama
    if lowered in _TEV_CACHE:
        return _TEV_CACHE[lowered]

    preview = (lowered[:50] + "...") if len(lowered) > 50 else lowered
    _TEV_COUNTER += 1
    start_time = time.time()
    try:
        body = json.dumps({"model": model, "state": lowered, "questions": TEV_QUESTIONS}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        elapsed = time.time() - start_time
        answers = data.get("answers", {})
        intent_info = answers.get("intent", {})
        choice = intent_info.get("choice", "other")
        confidence = intent_info.get("confidence", 0.0)
        noul = answers.get("authorizes_deletion", {}).get("noul", 0.0)
        authorizes = (choice == "deletion") and (noul >= 0.5)
        result = {
            "intent": choice,
            "confidence": confidence,
            "authorizes_deletion": noul,
            "authorizes": authorizes,
        }
        _TEV_CACHE[lowered] = result
        _save_cache()
        print(
            f"  [Tev #{_TEV_COUNTER}] {choice:16} (conf: {confidence:.3f}, {elapsed:.1f}s) | \"{preview}\"",
            file=sys.stderr,
            flush=True,
        )
        return result
    except Exception as exc:
        logger.warning("Tev decision model call failed (%s); falling back to regex", exc)
        return None


def request_authorizes_deletion_tev(text: str, model: str = "tev1:4b") -> bool | None:
    """Returns boolean decision from Tev model, or None if service unreachable."""
    res = classify_intent_tev(text, model=model)
    if res is None:
        return None
    return res["authorizes"]


def request_authorizes_deletion(text: str, engine: str | None = None) -> bool:
    """Evaluates whether the request text authorizes account deletion.

    Priority:
        1. Primary: Tev decision model (via local Ollama /v1/systemone with exact-string cache).
        2. Fallback: Deterministic regex engine (used if Ollama is unreachable, or if forced).
    """
    if engine == "regex" or os.environ.get("USE_REGEX") == "1":
        return request_authorizes_deletion_regex(text)

    # First check in-memory / persistent cache (instant)
    lowered = (text or "").strip()
    if lowered in _TEV_CACHE:
        return _TEV_CACHE[lowered]["authorizes"]

    # First option: Tev if Ollama is active or explicitly requested
    if check_tev_available() or engine == "tev":
        tev_decision = request_authorizes_deletion_tev(text)
        if tev_decision is not None:
            return tev_decision

    # Fallback option: Deterministic regex
    return request_authorizes_deletion_regex(text)
