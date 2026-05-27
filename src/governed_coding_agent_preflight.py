"""
Governed Coding Agent Preflight Wrapper v1.

Before any local command proposed by an external coding agent (Claude, Codex, …)
can proceed, PFC must produce a preflight decision and receipt.  This module is
still advisory/simulation-only: no command is ever executed.

Flow
----
1. The caller supplies a parent intent (already evaluated by the intent adapter)
   together with a proposed_command, command_type, target_paths, and
   requires_human_approval.
2. The parent intent receipt is re-validated: the parent decision must be
   INTENT_ADVISORY_ACCEPTED and the parent_intent_receipt_hash is required.
3. The proposed_command is checked against a deny-list of dangerous verbs.
4. The command_type must be one of the allowed simulated-only types.
5. Every target_path must be repo-relative and must not touch secrets, deploy,
   prod, credentials, CI/infrastructure paths.
6. A preflight receipt is emitted.  The receipt carries structural invariant
   flags regardless of the decision outcome:
       command_executed=False
       command_permitted=False
       real_authority_granted=False
       human_approval_required=True

PFC remains the execution boundary.  This module never runs a shell command,
touches the file system, calls the network, accesses credentials, or pushes
to Git.
"""
from __future__ import annotations

import re
from typing import Any

from src.governance_decision import DENY
from src.governance_hashing import deterministic_hash
from src.governed_coding_agent_intent import (
    INTENT_ADVISORY_ACCEPTED,
    _path_safe,                     # reuse identical path predicate
    evaluate_coding_agent_intent,
    validate_coding_agent_intent,
)

# ── public decision token ──────────────────────────────────────────────────
PREFLIGHT_ADVISORY_ACCEPTED = "PREFLIGHT_ADVISORY_ACCEPTED"

# ── allowed simulated command types ───────────────────────────────────────
ALLOWED_COMMAND_TYPES: frozenset[str] = frozenset(
    {
        "inspect_diff",
        "run_focused_tests",
        "propose_commit",
    }
)

# ── denied command verb patterns ───────────────────────────────────────────
# Any proposed_command whose normalised form matches one of these patterns is
# denied outright before any further check is performed.
_DENIED_COMMAND_PATTERNS: list[re.Pattern[str]] = [
    # git mutations
    re.compile(r"\bgit\s+(push|merge|rebase|reset|clean|rm|mv|tag|archive|bundle|gc|prune|reflog|bisect|stash\s+drop|worktree\s+add)\b", re.IGNORECASE),
    # deploy / release tooling
    re.compile(r"\b(deploy|release|publish|ship|rollout|kubectl\s+apply|helm\s+upgrade|ansible(-playbook)?|terraform\s+(apply|destroy))\b", re.IGNORECASE),
    # package registry pushes
    re.compile(r"\b(npm\s+publish|yarn\s+publish|pip\s+(upload|install\s+--index-url)|twine\s+upload|docker\s+(push|tag|build))\b", re.IGNORECASE),
    # network / remote access
    re.compile(r"\b(curl|wget|ssh|scp|sftp|rsync|nc|netcat|socat|telnet|ftp)\b", re.IGNORECASE),
    # privilege escalation
    re.compile(r"\b(sudo|su\s|doas|pkexec|runas)\b", re.IGNORECASE),
    # file-permission mutation
    re.compile(r"\b(chmod|chown|chgrp|setfacl|icacls)\b", re.IGNORECASE),
    # destructive file operations
    re.compile(r"\brm\s+(-[rRf]{1,3}\s+|--recursive\s+|--force\s+)", re.IGNORECASE),
    re.compile(r"\bshred\b|\bwipe\b|\bdd\s+if=", re.IGNORECASE),
    # secret / credential access tools
    re.compile(r"\b(aws\s+(sts|secretsmanager|ssm)|az\s+keyvault|gcloud\s+secrets|vault\s+(read|write|delete))\b", re.IGNORECASE),
    re.compile(r"\b(keyring|secret-tool|pass\s+(show|insert|rm))\b", re.IGNORECASE),
    # environment variable exfiltration
    re.compile(r"\benv\b.*>|\bprintenv\b.*>|\bset\b.*>", re.IGNORECASE),
    # production-targeting keywords in the command string itself
    re.compile(r"\b(production|--env\s+prod|--environment\s+prod|-e\s+prod)\b", re.IGNORECASE),
]


# ── structural invariant flags ─────────────────────────────────────────────
# These appear verbatim on every preflight receipt regardless of decision.
PREFLIGHT_FLAGS: dict[str, bool | str] = {
    "command_executed": False,
    "command_permitted": False,
    "real_authority_granted": False,
    "human_approval_required": True,
    "git_push_performed": False,
    "deployment_performed": False,
    "network_call_performed": False,
    "credential_access_performed": False,
}


# ── internal predicates ────────────────────────────────────────────────────

def _parent_intent_accepted(parent_receipt: Any) -> bool:
    """Return True iff the parent intent receipt carries INTENT_ADVISORY_ACCEPTED."""
    return (
        isinstance(parent_receipt, dict)
        and parent_receipt.get("decision") == INTENT_ADVISORY_ACCEPTED
        and parent_receipt.get("advisory_only") is True
        and parent_receipt.get("execution_performed") is False
        and parent_receipt.get("real_authority_granted") is False
    )


def _parent_receipt_hash_valid(parent_receipt: Any, provided_hash: Any) -> bool:
    """
    Return True iff provided_hash is a non-empty string that matches the
    receipt_hash stored inside parent_receipt.
    """
    if not isinstance(provided_hash, str) or not provided_hash.strip():
        return False
    if not isinstance(parent_receipt, dict):
        return False
    return parent_receipt.get("receipt_hash") == provided_hash


def _command_type_allowed(command_type: Any) -> bool:
    return isinstance(command_type, str) and command_type in ALLOWED_COMMAND_TYPES


def _command_safe(proposed_command: Any) -> bool:
    """
    Return True iff proposed_command is a non-empty string that does not match
    any of the denied-command patterns.
    """
    if not isinstance(proposed_command, str) or not proposed_command.strip():
        return False
    return not any(p.search(proposed_command) for p in _DENIED_COMMAND_PATTERNS)


def _all_paths_safe(target_paths: Any) -> bool:
    """
    Return True iff target_paths is a non-empty list of strings that all pass
    the path-safety predicate imported from the intent adapter.
    """
    if not isinstance(target_paths, list) or not target_paths:
        return False
    return all(_path_safe(p) for p in target_paths)


def _requires_human_approval_set(requires_human_approval: Any) -> bool:
    return requires_human_approval is True


# ── preflight validation ───────────────────────────────────────────────────

def validate_coding_agent_preflight(
    coding_agent_intent: dict[str, Any],
    parent_intent_receipt: dict[str, Any],
    parent_intent_receipt_hash: str | None,
    proposed_command: str | None,
    command_type: str | None,
    target_paths: list[str] | None,
    requires_human_approval: Any,
) -> dict[str, Any]:
    """
    Validate a preflight request against PFC governance rules.

    Parameters
    ----------
    coding_agent_intent:
        The original intent dict submitted by the external agent.
    parent_intent_receipt:
        The receipt previously produced by ``evaluate_coding_agent_intent``.
    parent_intent_receipt_hash:
        The caller-supplied ``receipt_hash`` from the parent receipt (used to
        prove the receipt has not been tampered with).
    proposed_command:
        The raw command string proposed for eventual human review.
    command_type:
        One of the allowed simulated command types.
    target_paths:
        List of repo-relative paths the command would touch.
    requires_human_approval:
        Must be strictly ``True``.

    Returns
    -------
    dict with keys:
        decision       – PREFLIGHT_ADVISORY_ACCEPTED or DENY
        checks         – per-rule boolean results
        reason_codes   – sorted list of denial reason-code strings
        command_executed   – always False
        command_permitted  – always False
    """
    # Re-validate the parent intent inline as an extra defence-in-depth check.
    intent_validation = validate_coding_agent_intent(coding_agent_intent)

    checks: dict[str, bool] = {
        "parent_intent_accepted": _parent_intent_accepted(parent_intent_receipt),
        "parent_receipt_hash_valid": _parent_receipt_hash_valid(
            parent_intent_receipt, parent_intent_receipt_hash
        ),
        "intent_revalidation_passed": intent_validation.get("decision") == INTENT_ADVISORY_ACCEPTED,
        "requires_human_approval_set": _requires_human_approval_set(requires_human_approval),
        "command_type_allowed": _command_type_allowed(command_type),
        "command_safe": _command_safe(proposed_command),
        "all_paths_safe": _all_paths_safe(target_paths),
    }

    reason_codes: list[str] = []

    if not checks["parent_intent_accepted"]:
        reason_codes.append("PARENT_INTENT_NOT_ACCEPTED")
    if not checks["parent_receipt_hash_valid"]:
        reason_codes.append("PARENT_RECEIPT_HASH_MISSING_OR_INVALID")
    if not checks["intent_revalidation_passed"]:
        reason_codes.append("INTENT_REVALIDATION_FAILED")
    if not checks["requires_human_approval_set"]:
        reason_codes.append("HUMAN_APPROVAL_REQUIRED")
    if not checks["command_type_allowed"]:
        reason_codes.append("COMMAND_TYPE_NOT_PERMITTED")
    if not checks["command_safe"]:
        reason_codes.append("COMMAND_DENIED")
    if not checks["all_paths_safe"]:
        reason_codes.append("PATH_UNSAFE_OR_OUT_OF_SCOPE")

    decision = (
        PREFLIGHT_ADVISORY_ACCEPTED
        if all(checks.values()) and not reason_codes
        else DENY
    )

    return {
        "decision": decision,
        "checks": checks,
        "reason_codes": sorted(reason_codes),
        # structural invariants always present
        "command_executed": False,
        "command_permitted": False,
    }


# ── preflight receipt generator ────────────────────────────────────────────

def generate_preflight_receipt(
    preflight_id: str,
    coding_agent_intent: dict[str, Any],
    parent_intent_receipt_hash: str | None,
    proposed_command: str | None,
    command_type: str | None,
    target_paths: list[str] | None,
    validation: dict[str, Any],
    *,
    prev_preflight_receipt_hash: str | None = None,
) -> dict[str, Any]:
    """
    Generate a deterministic, hash-linked preflight receipt.

    The receipt captures the preflight identity, parent intent linkage,
    governance decision, all check results, reason codes, structural invariant
    flags, and a SHA-256 ``receipt_hash`` that covers all other fields.

    Parameters
    ----------
    preflight_id:
        Unique identifier for this preflight evaluation.
    coding_agent_intent:
        The original intent dict (identity fields only; no execution).
    parent_intent_receipt_hash:
        The hash supplied by the caller linking this preflight to its parent
        intent receipt.
    proposed_command:
        The raw command string under review (not executed).
    command_type:
        The simulated command type.
    target_paths:
        The paths the command would touch.
    validation:
        The result of ``validate_coding_agent_preflight``.
    prev_preflight_receipt_hash:
        Optional hash of the immediately preceding preflight receipt for
        lineage chaining.

    Returns
    -------
    Immutable receipt dict.  ``receipt_hash`` covers all other fields.
    """
    decision = validation.get("decision", DENY)
    checks = validation.get("checks", {})
    reason_codes = validation.get("reason_codes", ["PREFLIGHT_VALIDATION_MISSING"])

    receipt: dict[str, Any] = {
        # preflight identity
        "preflight_id": preflight_id,
        # parent intent linkage
        "parent_intent_id": coding_agent_intent.get("intent_id"),
        "parent_agent_id": coding_agent_intent.get("agent_id"),
        "parent_agent_type": coding_agent_intent.get("agent_type"),
        "parent_intent_receipt_hash": parent_intent_receipt_hash,
        # command under review (advisory copy only; not executed)
        "proposed_command": proposed_command,
        "command_type": command_type,
        "target_paths": target_paths or [],
        # governance outcome
        "decision": decision,
        "checks": checks,
        "reason_codes": sorted(reason_codes),
        # structural invariant flags
        **PREFLIGHT_FLAGS,
    }

    if prev_preflight_receipt_hash is not None:
        receipt["prev_preflight_receipt_hash"] = prev_preflight_receipt_hash

    # Hash covers all fields above; appended last.
    receipt["receipt_hash"] = deterministic_hash(receipt)
    return receipt


# ── convenience entry-point ────────────────────────────────────────────────

def evaluate_coding_agent_preflight(
    preflight_id: str,
    coding_agent_intent: dict[str, Any],
    parent_intent_receipt: dict[str, Any],
    parent_intent_receipt_hash: str | None,
    proposed_command: str | None,
    command_type: str | None,
    target_paths: list[str] | None,
    requires_human_approval: Any,
    *,
    prev_preflight_receipt_hash: str | None = None,
) -> dict[str, Any]:
    """
    Validate a coding agent preflight request and return a governed receipt.

    This is the single public entry-point: validate → receipt.  The receipt
    always carries ``command_executed=False``, ``command_permitted=False``, and
    ``real_authority_granted=False`` as structural invariants.

    Parameters
    ----------
    preflight_id:
        Unique identifier for this preflight evaluation.
    coding_agent_intent:
        The original intent dict as submitted by the external agent.
    parent_intent_receipt:
        The receipt produced by ``evaluate_coding_agent_intent``.
    parent_intent_receipt_hash:
        The ``receipt_hash`` from the parent intent receipt.
    proposed_command:
        The raw command string proposed by the agent.
    command_type:
        One of the allowed simulated command types.
    target_paths:
        List of repo-relative paths the command would touch.
    requires_human_approval:
        Must be strictly ``True``.
    prev_preflight_receipt_hash:
        Optional hash of the prior preflight receipt for lineage chaining.

    Returns
    -------
    Governed preflight receipt dict with a deterministic ``receipt_hash``.
    """
    validation = validate_coding_agent_preflight(
        coding_agent_intent=coding_agent_intent,
        parent_intent_receipt=parent_intent_receipt,
        parent_intent_receipt_hash=parent_intent_receipt_hash,
        proposed_command=proposed_command,
        command_type=command_type,
        target_paths=target_paths,
        requires_human_approval=requires_human_approval,
    )
    return generate_preflight_receipt(
        preflight_id=preflight_id,
        coding_agent_intent=coding_agent_intent,
        parent_intent_receipt_hash=parent_intent_receipt_hash,
        proposed_command=proposed_command,
        command_type=command_type,
        target_paths=target_paths,
        validation=validation,
        prev_preflight_receipt_hash=prev_preflight_receipt_hash,
    )
