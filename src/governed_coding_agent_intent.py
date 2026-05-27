"""
Governed Coding Agent Intent Adapter v1.

Models, validates, and receipts advisory-only intent from external coding agents
(e.g. Claude, Codex).  PFC remains the execution boundary; this module never
grants real execution authority, Git push, network calls, credential access,
deployment authority, or production mutation.

All validated intents that pass return ``INTENT_ADVISORY_ACCEPTED`` together
with an immutable receipt hash.  Denied intents return ``DENY`` with reason
codes.  In both cases ``execution_performed=False`` and
``real_authority_granted=False`` are structural invariants of every receipt.
"""
from __future__ import annotations

import re
from typing import Any

from src.governance_decision import DENY
from src.governance_hashing import deterministic_hash

# ── public decision token ──────────────────────────────────────────────────
INTENT_ADVISORY_ACCEPTED = "INTENT_ADVISORY_ACCEPTED"

# ── allowed action vocabulary ──────────────────────────────────────────────
ALLOWED_ACTIONS: frozenset[str] = frozenset(
    {
        "propose_file_change",
        "propose_test_run",
        "propose_commit",
    }
)

# ── risk-level ordering ────────────────────────────────────────────────────
# Anything above "bounded" is denied.
_RISK_ORDER: list[str] = ["low", "bounded", "high", "critical"]
_ALLOWED_RISK_LEVELS: frozenset[str] = frozenset({"low", "bounded"})

# ── forbidden path patterns ────────────────────────────────────────────────
# target_path must not reference secrets, credentials, env files, deploy
# configs, or production paths, and must not escape the repository root.
_FORBIDDEN_PATH_PATTERNS: list[re.Pattern[str]] = [
    # path traversal – catches ../ and ..\
    re.compile(r"\.\.([\\/]|$)"),
    # hidden .env files and variants
    re.compile(r"(^|[/\\])\.env(\b|\.|\Z)", re.IGNORECASE),
    # secrets / credentials directories or files
    re.compile(r"(^|[/\\])secrets?([\\/]|\Z)", re.IGNORECASE),
    re.compile(r"(^|[/\\])credentials?([\\/]|\Z)", re.IGNORECASE),
    # deploy / deployment directories or scripts
    re.compile(r"(^|[/\\])deploy(ment)?([\\/]|\Z)", re.IGNORECASE),
    # production / prod directories
    re.compile(r"(^|[/\\])prod(uction)?([\\/]|\Z)", re.IGNORECASE),
    # private-key file extensions
    re.compile(r"\.(key|pem|crt|p12|pfx)\Z", re.IGNORECASE),
    # well-known SSH / private-key filenames
    re.compile(
        r"(^|[/\\])(id_rsa|id_ed25519|id_dsa|id_ecdsa|authorized_keys|known_hosts)\Z",
        re.IGNORECASE,
    ),
    # infra / cloud config files at any depth
    re.compile(r"(^|[/\\])(terraform|ansible|k8s|kubernetes)([\\/]|\Z)", re.IGNORECASE),
    # CI/CD pipeline definitions that could trigger real deployment
    re.compile(r"(^|[/\\])\.(github|gitlab|circleci)([\\/]|\Z)", re.IGNORECASE),
]

# ── deterministic demo freshness constants ─────────────────────────────────
# All timestamps are fixed so receipts and tests remain fully deterministic.
# They demonstrate the freshness-verification pattern; they are not real-time
# access-control values.  See SECURITY.md for the known-limitation notice.
#
#   DEMO_ISSUED_AT   – the moment the demo receipt is "issued"
#   DEMO_TTL_SECONDS – how many seconds the receipt is considered fresh
#   DEMO_EXPIRES_AT  – DEMO_ISSUED_AT + DEMO_TTL_SECONDS  (01:00 UTC)
#   DEMO_CHECK_AT    – canonical demo "now"; 30 min after issuance, within TTL
DEMO_ISSUED_AT:   str = "2026-05-26T00:00:00Z"
DEMO_TTL_SECONDS: int = 3600
DEMO_EXPIRES_AT:  str = "2026-05-26T01:00:00Z"
DEMO_CHECK_AT:    str = "2026-05-26T00:30:00Z"  # within TTL; used as default check time

# ── structural invariant flags ─────────────────────────────────────────────
# These flags appear verbatim on every receipt regardless of decision outcome.
INTENT_FLAGS: dict[str, bool] = {
    "execution_performed": False,
    "execution_permitted": False,
    "real_authority_granted": False,
    "git_push_performed": False,
    "deployment_performed": False,
    "network_call_performed": False,
    "credential_access_performed": False,
}


# ── internal predicate functions ───────────────────────────────────────────

def _action_allowed(requested_action: Any) -> bool:
    """Return True iff requested_action is in the allowed advisory vocabulary."""
    return isinstance(requested_action, str) and requested_action in ALLOWED_ACTIONS


def _risk_within_bound(risk_level: Any) -> bool:
    """Return True iff risk_level is at most 'bounded'."""
    return isinstance(risk_level, str) and risk_level in _ALLOWED_RISK_LEVELS


def _path_safe(target_path: Any) -> bool:
    """
    Return True iff target_path is a non-empty string that does not escape the
    repository root and does not reference secrets, env files, credentials,
    deploy configs, or production paths.

    An absolute path (starting with '/') is always rejected because the repo
    root is relative.
    """
    if not isinstance(target_path, str) or not target_path.strip():
        return False
    # Absolute paths are not repo-relative
    if target_path.startswith("/") or (
        len(target_path) >= 3 and target_path[1] == ":" and target_path[2] in r"\/"
    ):
        return False
    # Check every forbidden pattern
    return not any(p.search(target_path) for p in _FORBIDDEN_PATH_PATTERNS)


def _advisory_flag_set(advisory_only: Any) -> bool:
    return advisory_only is True


def _human_review_required_set(human_review_required: Any) -> bool:
    return human_review_required is True


# ── validation ─────────────────────────────────────────────────────────────

def validate_coding_agent_intent(intent: dict[str, Any]) -> dict[str, Any]:
    """
    Validate an external coding agent intent dict against PFC governance rules.

    Parameters
    ----------
    intent:
        Dict with at minimum the keys defined in the intent schema:
        agent_id, agent_type, intent_id, requested_action, target_path,
        scope, risk_level, human_review_required, advisory_only.

    Returns
    -------
    dict with keys:
        decision       – INTENT_ADVISORY_ACCEPTED or DENY
        checks         – per-rule boolean results
        reason_codes   – list of string codes explaining any denial
        advisory_only  – always True (structural invariant)
    """
    if not isinstance(intent, dict):
        return {
            "decision": DENY,
            "checks": {},
            "reason_codes": ["INTENT_MALFORMED"],
            "advisory_only": True,
        }

    checks: dict[str, bool] = {
        "intent_id_present": bool(intent.get("intent_id")),
        "agent_id_present": bool(intent.get("agent_id")),
        "agent_type_present": bool(intent.get("agent_type")),
        "advisory_only_set": _advisory_flag_set(intent.get("advisory_only")),
        "human_review_required_set": _human_review_required_set(
            intent.get("human_review_required")
        ),
        "action_allowed": _action_allowed(intent.get("requested_action")),
        "risk_within_bound": _risk_within_bound(intent.get("risk_level")),
        "path_safe": _path_safe(intent.get("target_path")),
    }

    reason_codes: list[str] = []

    if not checks["intent_id_present"]:
        reason_codes.append("INTENT_ID_MISSING")
    if not checks["agent_id_present"]:
        reason_codes.append("AGENT_ID_MISSING")
    if not checks["agent_type_present"]:
        reason_codes.append("AGENT_TYPE_MISSING")
    if not checks["advisory_only_set"]:
        reason_codes.append("ADVISORY_ONLY_REQUIRED")
    if not checks["human_review_required_set"]:
        reason_codes.append("HUMAN_REVIEW_REQUIRED")
    if not checks["action_allowed"]:
        reason_codes.append("ACTION_NOT_PERMITTED")
    if not checks["risk_within_bound"]:
        reason_codes.append("RISK_LEVEL_EXCEEDS_BOUND")
    if not checks["path_safe"]:
        reason_codes.append("PATH_UNSAFE_OR_OUT_OF_SCOPE")

    decision = (
        INTENT_ADVISORY_ACCEPTED
        if all(checks.values()) and not reason_codes
        else DENY
    )

    return {
        "decision": decision,
        "checks": checks,
        "reason_codes": sorted(reason_codes),
        "advisory_only": True,
    }


# ── receipt generator ──────────────────────────────────────────────────────

def generate_intent_receipt(
    intent: dict[str, Any],
    validation: dict[str, Any],
    *,
    prev_receipt_hash: str | None = None,
) -> dict[str, Any]:
    """
    Generate a deterministic, immutable receipt for an evaluated coding agent
    intent.

    The receipt captures the intent identity, governance decision, all check
    results, reason codes, no-execution invariant flags, and a SHA-256 hash
    of the receipt payload.  The hash is computed last so it covers the full
    receipt content.

    Parameters
    ----------
    intent:
        The raw intent dict as submitted by the external agent.
    validation:
        The result of ``validate_coding_agent_intent(intent)``.
    prev_receipt_hash:
        Optional hash of the immediately preceding receipt for lineage chaining.

    Returns
    -------
    Immutable receipt dict.  ``receipt_hash`` covers all other fields.
    """
    # Defensive: ensure invariants even if caller passes a bad validation dict
    decision = validation.get("decision", DENY)
    checks = validation.get("checks", {})
    reason_codes = validation.get("reason_codes", ["RECEIPT_VALIDATION_MISSING"])

    receipt: dict[str, Any] = {
        # identity
        "intent_id": intent.get("intent_id"),
        "agent_id": intent.get("agent_id"),
        "agent_type": intent.get("agent_type"),
        # intent fields (advisory copies only; no execution)
        "requested_action": intent.get("requested_action"),
        "target_path": intent.get("target_path"),
        "scope": intent.get("scope"),
        "risk_level": intent.get("risk_level"),
        "human_review_required": intent.get("human_review_required"),
        # freshness – fixed demo constants; covered by receipt_hash
        "issued_at":   DEMO_ISSUED_AT,
        "expires_at":  DEMO_EXPIRES_AT,
        "ttl_seconds": DEMO_TTL_SECONDS,
        # governance outcome
        "decision": decision,
        "checks": checks,
        "reason_codes": sorted(reason_codes),
        # structural invariant flags – always False / True
        **INTENT_FLAGS,
        "advisory_only": True,
    }

    if prev_receipt_hash is not None:
        receipt["prev_receipt_hash"] = prev_receipt_hash

    # The hash covers all fields above; it is appended last.
    receipt["receipt_hash"] = deterministic_hash(receipt)
    return receipt


# ── convenience entry-point ────────────────────────────────────────────────

def evaluate_coding_agent_intent(
    intent: dict[str, Any],
    *,
    prev_receipt_hash: str | None = None,
) -> dict[str, Any]:
    """
    Validate an external coding agent intent and return a governed receipt.

    This is the single public entry-point: validate → receipt.  The receipt
    always preserves ``execution_performed=False`` and
    ``real_authority_granted=False``.

    Parameters
    ----------
    intent:
        Intent dict from an external coding agent.
    prev_receipt_hash:
        Optional SHA-256 hash of the prior receipt for lineage chaining.

    Returns
    -------
    Governed receipt dict with a deterministic ``receipt_hash``.
    """
    validation = validate_coding_agent_intent(intent)
    return generate_intent_receipt(intent, validation, prev_receipt_hash=prev_receipt_hash)
