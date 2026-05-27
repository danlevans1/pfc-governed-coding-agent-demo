"""
Governed Coding Agent Preflight Replay Verifier v1.

Receipts are not trusted merely because they exist; they must replay to the
same deterministic decision.

This module independently recomputes a preflight receipt from its raw inputs
and verifies that every material field in the stored receipt matches the
recomputed receipt.  It is entirely advisory/simulation-only:

  - No command is executed.
  - No file is mutated.
  - No network call is made.
  - No credential is accessed.
  - No Git push is performed.
  - No authority is granted.

Verification flow
-----------------
1.  Validate the stored_preflight_receipt structure (non-empty dict, receipt_hash
    present).
2.  Check that the stored receipt does not claim any forbidden flags
    (``command_executed=True``, ``command_permitted=True``,
    ``real_authority_granted=True``).
3.  Re-run ``evaluate_coding_agent_preflight`` from the governed_coding_agent_preflight
    module with the original raw inputs to produce a recomputed receipt.
4.  Compare field-by-field: decision, reason_codes, command_type, target_paths,
    parent_intent_receipt_hash, prev_preflight_receipt_hash, and the terminal
    receipt_hash.
5.  Return ``REPLAY_VERIFIED`` only if every check passes.
    Return ``DENY`` with reason codes if anything differs.

The replay verification receipt itself carries its own ``receipt_hash`` so
that replay audits can be chained.
"""
from __future__ import annotations

from typing import Any

from src.governance_decision import DENY
from src.governance_hashing import deterministic_hash
from src.governed_coding_agent_intent import DEMO_CHECK_AT
from src.governed_coding_agent_preflight import (
    PREFLIGHT_FLAGS,
    evaluate_coding_agent_preflight,
)

# ── public decision token ──────────────────────────────────────────────────
REPLAY_VERIFIED = "REPLAY_VERIFIED"

# ── structural invariant flags for the replay receipt itself ───────────────
# These are separate from PREFLIGHT_FLAGS: they describe the replay evaluation,
# not the original preflight.
REPLAY_FLAGS: dict[str, bool] = {
    "command_executed": False,
    "command_permitted": False,
    "real_authority_granted": False,
    "execution_performed": False,
    "git_push_performed": False,
    "deployment_performed": False,
    "network_call_performed": False,
    "credential_access_performed": False,
}

# ── fields compared between stored and recomputed receipt ─────────────────
_COMPARED_FIELDS: tuple[str, ...] = (
    "decision",
    "reason_codes",
    "command_type",
    "target_paths",
    "parent_intent_receipt_hash",
    "command_executed",
    "command_permitted",
    "real_authority_granted",
    "human_approval_required",
    "receipt_hash",
)


# ── internal helpers ───────────────────────────────────────────────────────

def _stored_receipt_present(stored: Any) -> bool:
    """Return True iff stored receipt is a non-empty dict with a receipt_hash."""
    return (
        isinstance(stored, dict)
        and bool(stored)
        and isinstance(stored.get("receipt_hash"), str)
        and bool(stored["receipt_hash"].strip())
    )


def _prev_hash_matches(stored: dict[str, Any], recomputed: dict[str, Any]) -> bool:
    """
    Return True iff the optional prev_preflight_receipt_hash field is consistent
    between stored and recomputed receipts.

    Both absent  → match.
    One absent   → mismatch.
    Both present → must be equal.
    """
    stored_has = "prev_preflight_receipt_hash" in stored
    recomputed_has = "prev_preflight_receipt_hash" in recomputed
    if stored_has != recomputed_has:
        return False
    if not stored_has:
        return True
    return stored["prev_preflight_receipt_hash"] == recomputed["prev_preflight_receipt_hash"]


# ── core verifier ──────────────────────────────────────────────────────────

def verify_preflight_replay(
    coding_agent_intent: dict[str, Any],
    parent_intent_receipt: dict[str, Any],
    preflight_request: dict[str, Any],
    stored_preflight_receipt: Any,
    *,
    check_at: str = DEMO_CHECK_AT,
) -> dict[str, Any]:
    """
    Verify that a stored preflight receipt is consistent with a fresh replay.

    Parameters
    ----------
    coding_agent_intent:
        The original intent dict as submitted by the external agent.
    parent_intent_receipt:
        The parent intent receipt that was used during the original preflight.
    preflight_request:
        Dict of original preflight request fields:
          - preflight_id                 (str)
          - proposed_command             (str | None)
          - command_type                 (str | None)
          - target_paths                 (list[str] | None)
          - requires_human_approval      (bool)
          - parent_intent_receipt_hash   (str | None)
          - prev_preflight_receipt_hash  (str | None, optional)
    stored_preflight_receipt:
        The previously emitted preflight receipt dict to verify.
    check_at:
        ISO-8601 UTC timestamp string used to evaluate receipt freshness.
        Defaults to ``DEMO_CHECK_AT`` (a fixed demo constant within the demo
        TTL window) so that all default-path tests remain deterministic.
        Pass an explicit value to test expiry behaviour.

    Returns
    -------
    A replay verification receipt dict.  Key fields:
        decision      – REPLAY_VERIFIED or DENY
        check_at      – the freshness-check timestamp used in this evaluation
        replay_checks – per-check boolean results
        reason_codes  – sorted list of denial reason-code strings
        receipt_hash  – SHA-256 hash covering all other fields in this receipt
    All REPLAY_FLAGS invariants are always present regardless of outcome.
    """
    # ── extract preflight request fields ────────────────────────────────────
    preflight_id: str = preflight_request.get("preflight_id", "")
    proposed_command = preflight_request.get("proposed_command")
    command_type = preflight_request.get("command_type")
    target_paths = preflight_request.get("target_paths")
    requires_human_approval = preflight_request.get("requires_human_approval", False)
    parent_intent_receipt_hash = preflight_request.get("parent_intent_receipt_hash")
    prev_preflight_receipt_hash = preflight_request.get("prev_preflight_receipt_hash")

    # ── phase 1: pre-replay checks on the stored receipt ────────────────────
    stored_present = _stored_receipt_present(stored_preflight_receipt)

    # Guard: if stored receipt is missing/malformed, skip field comparisons.
    stored: dict[str, Any] = stored_preflight_receipt if isinstance(stored_preflight_receipt, dict) else {}

    # Freshness check: the stored receipt's expires_at must be strictly later
    # than check_at.  ISO-8601 UTC strings compare lexicographically correctly.
    _expires_at = stored.get("expires_at", "")
    _receipt_not_expired = bool(_expires_at) and _expires_at > check_at

    pre_checks: dict[str, bool] = {
        "stored_receipt_present": stored_present,
        "stored_command_executed_false": stored.get("command_executed") is False,
        "stored_command_permitted_false": stored.get("command_permitted") is False,
        "stored_real_authority_granted_false": stored.get("real_authority_granted") is False,
        "receipt_not_expired": _receipt_not_expired,
    }

    # ── phase 2: replay ──────────────────────────────────────────────────────
    recomputed: dict[str, Any] = evaluate_coding_agent_preflight(
        preflight_id=preflight_id,
        coding_agent_intent=coding_agent_intent,
        parent_intent_receipt=parent_intent_receipt,
        parent_intent_receipt_hash=parent_intent_receipt_hash,
        proposed_command=proposed_command,
        command_type=command_type,
        target_paths=target_paths,
        requires_human_approval=requires_human_approval,
        prev_preflight_receipt_hash=prev_preflight_receipt_hash,
    )

    # ── phase 3: field-by-field comparison ───────────────────────────────────
    field_checks: dict[str, bool] = {
        f"field_{field}_matches": stored.get(field) == recomputed.get(field)
        for field in _COMPARED_FIELDS
    }
    prev_hash_check: dict[str, bool] = {
        "prev_preflight_receipt_hash_matches": _prev_hash_matches(stored, recomputed),
    }

    replay_checks: dict[str, bool] = {**pre_checks, **field_checks, **prev_hash_check}

    # ── phase 4: reason codes ────────────────────────────────────────────────
    reason_codes: list[str] = []

    if not replay_checks["stored_receipt_present"]:
        reason_codes.append("STORED_RECEIPT_MISSING_OR_MALFORMED")
    if not replay_checks["stored_command_executed_false"]:
        reason_codes.append("STORED_RECEIPT_CLAIMS_COMMAND_EXECUTED")
    if not replay_checks["stored_command_permitted_false"]:
        reason_codes.append("STORED_RECEIPT_CLAIMS_COMMAND_PERMITTED")
    if not replay_checks["stored_real_authority_granted_false"]:
        reason_codes.append("STORED_RECEIPT_CLAIMS_REAL_AUTHORITY_GRANTED")
    if not replay_checks["receipt_not_expired"]:
        reason_codes.append("RECEIPT_EXPIRED")
    if not replay_checks["field_decision_matches"]:
        reason_codes.append("DECISION_MISMATCH")
    if not replay_checks["field_reason_codes_matches"]:
        reason_codes.append("REASON_CODES_MISMATCH")
    if not replay_checks["field_command_type_matches"]:
        reason_codes.append("COMMAND_TYPE_MISMATCH")
    if not replay_checks["field_target_paths_matches"]:
        reason_codes.append("TARGET_PATHS_MISMATCH")
    if not replay_checks["field_parent_intent_receipt_hash_matches"]:
        reason_codes.append("PARENT_INTENT_RECEIPT_HASH_MISMATCH")
    if not replay_checks["field_command_executed_matches"]:
        reason_codes.append("COMMAND_EXECUTED_FLAG_MISMATCH")
    if not replay_checks["field_command_permitted_matches"]:
        reason_codes.append("COMMAND_PERMITTED_FLAG_MISMATCH")
    if not replay_checks["field_real_authority_granted_matches"]:
        reason_codes.append("REAL_AUTHORITY_GRANTED_FLAG_MISMATCH")
    if not replay_checks["field_human_approval_required_matches"]:
        reason_codes.append("HUMAN_APPROVAL_REQUIRED_FLAG_MISMATCH")
    if not replay_checks["field_receipt_hash_matches"]:
        reason_codes.append("RECEIPT_HASH_MISMATCH")
    if not replay_checks["prev_preflight_receipt_hash_matches"]:
        reason_codes.append("PREV_PREFLIGHT_RECEIPT_HASH_MISMATCH")

    decision = REPLAY_VERIFIED if all(replay_checks.values()) and not reason_codes else DENY

    # ── build replay verification receipt ────────────────────────────────────
    replay_receipt: dict[str, Any] = {
        "preflight_id": preflight_id,
        "stored_receipt_hash": stored.get("receipt_hash"),
        "recomputed_receipt_hash": recomputed.get("receipt_hash"),
        # check_at is recorded for audit trail; included in receipt_hash
        "check_at": check_at,
        "decision": decision,
        "replay_checks": replay_checks,
        "reason_codes": sorted(reason_codes),
        **REPLAY_FLAGS,
    }
    replay_receipt["receipt_hash"] = deterministic_hash(replay_receipt)
    return replay_receipt
