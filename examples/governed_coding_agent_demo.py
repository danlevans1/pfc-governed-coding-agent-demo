"""
Governed Coding Agent End-to-End Demo
======================================
Demonstrates the complete bounded proof chain for external coding agents:

    Claude/Codex intent
    → PFC intent receipt          (governed_coding_agent_intent)
    → PFC preflight receipt       (governed_coding_agent_preflight)
    → PFC replay verification     (governed_coding_agent_preflight_replay)
    → dangerous command denial    (governed_coding_agent_preflight)

This demo is advisory/simulation-only.  It does NOT:
  - execute shell commands
  - mutate files
  - push to Git
  - deploy anything
  - call the network
  - access credentials
  - grant execution authority

All decisions are deterministic.  Every receipt is hash-linked.
PFC remains the execution boundary throughout.

Scenarios
---------
A  Valid Claude intent → accepted intent receipt → accepted preflight → REPLAY_VERIFIED
B  Valid Codex intent  → dangerous command (git push) → preflight DENY
C  Valid preflight     → tampered receipt (real_authority_granted=True) → replay DENY

Usage
-----
    python -m examples.governed_coding_agent_demo          # pretty output
    python -m examples.governed_coding_agent_demo --quiet  # suppress print
"""
from __future__ import annotations

import sys
import textwrap
from typing import Any

from src.governed_coding_agent_intent import (
    INTENT_ADVISORY_ACCEPTED,
    evaluate_coding_agent_intent,
)
from src.governed_coding_agent_preflight import (
    PREFLIGHT_ADVISORY_ACCEPTED,
    evaluate_coding_agent_preflight,
)
from src.governed_coding_agent_preflight_replay import (
    REPLAY_VERIFIED,
    verify_preflight_replay,
)
from src.governance_decision import DENY

# ── no-execution invariant keys (must be False on every receipt) ───────────
_MUST_BE_FALSE = (
    "execution_performed",
    "command_executed",
    "command_permitted",
    "real_authority_granted",
    "git_push_performed",
    "deployment_performed",
    "network_call_performed",
    "credential_access_performed",
)

# ─────────────────────────────────────────────────────────────────────────────
# Scenario A — accepted advisory flow
# ─────────────────────────────────────────────────────────────────────────────

def scenario_a() -> dict[str, Any]:
    """
    Happy-path: Claude proposes a test run.
    Returns a dict with intent_receipt, preflight_receipt, replay_receipt, and
    an 'ok' bool that is True only when all three decisions are the expected
    accepted/verified tokens.
    """
    # 1. Build a valid Claude intent ──────────────────────────────────────────
    intent = {
        "intent_id":             "demo-intent-A-001",
        "agent_id":              "claude-agent-demo",
        "agent_type":            "claude",
        "requested_action":      "propose_test_run",
        "target_path":           "tests/test_sample.py",
        "scope":                 {"context": "demo – scenario A"},
        "risk_level":            "low",
        "human_review_required": True,
        "advisory_only":         True,
    }

    # 2. Intent evaluation ────────────────────────────────────────────────────
    intent_receipt = evaluate_coding_agent_intent(intent)

    # 3. Build a safe preflight request ───────────────────────────────────────
    parent_hash = intent_receipt["receipt_hash"]
    preflight_request = {
        "preflight_id":               "demo-preflight-A-001",
        "proposed_command":           "pytest tests/test_sample.py -v",
        "command_type":               "run_focused_tests",
        "target_paths":               ["tests/test_sample.py"],
        "requires_human_approval":    True,
        "parent_intent_receipt_hash": parent_hash,
        "prev_preflight_receipt_hash": None,
    }

    # 4. Preflight evaluation ─────────────────────────────────────────────────
    preflight_receipt = evaluate_coding_agent_preflight(
        preflight_id=              preflight_request["preflight_id"],
        coding_agent_intent=       intent,
        parent_intent_receipt=     intent_receipt,
        parent_intent_receipt_hash=parent_hash,
        proposed_command=          preflight_request["proposed_command"],
        command_type=              preflight_request["command_type"],
        target_paths=              preflight_request["target_paths"],
        requires_human_approval=   preflight_request["requires_human_approval"],
    )

    # 5. Replay verification ──────────────────────────────────────────────────
    replay_receipt = verify_preflight_replay(
        coding_agent_intent=    intent,
        parent_intent_receipt=  intent_receipt,
        preflight_request=      preflight_request,
        stored_preflight_receipt=preflight_receipt,
    )

    ok = (
        intent_receipt["decision"]   == INTENT_ADVISORY_ACCEPTED
        and preflight_receipt["decision"] == PREFLIGHT_ADVISORY_ACCEPTED
        and replay_receipt["decision"]    == REPLAY_VERIFIED
    )

    return {
        "intent":            intent,
        "intent_receipt":    intent_receipt,
        "preflight_request": preflight_request,
        "preflight_receipt": preflight_receipt,
        "replay_receipt":    replay_receipt,
        "ok":                ok,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Scenario B — dangerous command denied
# ─────────────────────────────────────────────────────────────────────────────

def scenario_b() -> dict[str, Any]:
    """
    Codex proposes 'git push origin main'.
    Preflight must return DENY.
    Returns a dict with intent_receipt, preflight_receipt, and an 'ok' bool
    that is True when the preflight was correctly denied.
    """
    # 1. Valid Codex intent ───────────────────────────────────────────────────
    intent = {
        "intent_id":             "demo-intent-B-001",
        "agent_id":              "codex-agent-demo",
        "agent_type":            "codex",
        "requested_action":      "propose_commit",
        "target_path":           "src/module.py",
        "scope":                 {"context": "demo – scenario B"},
        "risk_level":            "bounded",
        "human_review_required": True,
        "advisory_only":         True,
    }

    # 2. Intent evaluation (should be accepted) ───────────────────────────────
    intent_receipt = evaluate_coding_agent_intent(intent)
    parent_hash = intent_receipt["receipt_hash"]

    # 3. Dangerous preflight request ──────────────────────────────────────────
    preflight_receipt = evaluate_coding_agent_preflight(
        preflight_id=               "demo-preflight-B-001",
        coding_agent_intent=        intent,
        parent_intent_receipt=      intent_receipt,
        parent_intent_receipt_hash= parent_hash,
        proposed_command=           "git push origin main",   # ← denied
        command_type=               "propose_commit",
        target_paths=               ["src/module.py"],
        requires_human_approval=    True,
    )

    ok = (
        intent_receipt["decision"]   == INTENT_ADVISORY_ACCEPTED
        and preflight_receipt["decision"] == DENY
        and "COMMAND_DENIED" in preflight_receipt["reason_codes"]
    )

    return {
        "intent":         intent,
        "intent_receipt": intent_receipt,
        "preflight_receipt": preflight_receipt,
        "ok":             ok,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Scenario C — tampered receipt denied by replay verifier
# ─────────────────────────────────────────────────────────────────────────────

def scenario_c() -> dict[str, Any]:
    """
    A valid preflight receipt is tampered (real_authority_granted set to True
    and receipt_hash corrupted).
    Replay verification must return DENY.
    Returns a dict with the original receipt, the tampered receipt, the replay
    result, and an 'ok' bool that is True when replay correctly catches the tamper.
    """
    # 1. Build a clean, valid preflight receipt ────────────────────────────────
    intent = {
        "intent_id":             "demo-intent-C-001",
        "agent_id":              "claude-agent-demo",
        "agent_type":            "claude",
        "requested_action":      "propose_file_change",
        "target_path":           "src/utils.py",
        "scope":                 {"context": "demo – scenario C"},
        "risk_level":            "low",
        "human_review_required": True,
        "advisory_only":         True,
    }
    intent_receipt = evaluate_coding_agent_intent(intent)
    parent_hash = intent_receipt["receipt_hash"]

    preflight_request = {
        "preflight_id":                "demo-preflight-C-001",
        "proposed_command":            "git diff HEAD src/utils.py",
        "command_type":                "inspect_diff",
        "target_paths":                ["src/utils.py"],
        "requires_human_approval":     True,
        "parent_intent_receipt_hash":  parent_hash,
        "prev_preflight_receipt_hash": None,
    }
    original_receipt = evaluate_coding_agent_preflight(
        preflight_id=               preflight_request["preflight_id"],
        coding_agent_intent=        intent,
        parent_intent_receipt=      intent_receipt,
        parent_intent_receipt_hash= parent_hash,
        proposed_command=           preflight_request["proposed_command"],
        command_type=               preflight_request["command_type"],
        target_paths=               preflight_request["target_paths"],
        requires_human_approval=    preflight_request["requires_human_approval"],
    )

    # 2. Tamper: claim execution authority and corrupt the hash ────────────────
    tampered_receipt = dict(original_receipt)
    tampered_receipt["real_authority_granted"] = True   # ← tamper
    tampered_receipt["command_permitted"]       = True   # ← tamper
    tampered_receipt["receipt_hash"]            = "00" * 32  # ← corrupted hash

    # 3. Replay verification catches the tamper ────────────────────────────────
    replay_receipt = verify_preflight_replay(
        coding_agent_intent=     intent,
        parent_intent_receipt=   intent_receipt,
        preflight_request=       preflight_request,
        stored_preflight_receipt=tampered_receipt,
    )

    ok = (
        replay_receipt["decision"] == DENY
        and "STORED_RECEIPT_CLAIMS_REAL_AUTHORITY_GRANTED" in replay_receipt["reason_codes"]
        and "STORED_RECEIPT_CLAIMS_COMMAND_PERMITTED"      in replay_receipt["reason_codes"]
        and "RECEIPT_HASH_MISMATCH"                        in replay_receipt["reason_codes"]
    )

    return {
        "intent":           intent,
        "intent_receipt":   intent_receipt,
        "original_receipt": original_receipt,
        "tampered_receipt": tampered_receipt,
        "replay_receipt":   replay_receipt,
        "ok":               ok,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Invariant checker (used by tests and pretty-printer alike)
# ─────────────────────────────────────────────────────────────────────────────

def check_no_execution_invariants(receipt: dict[str, Any]) -> dict[str, bool]:
    """
    Return a dict of {flag: True/False} for every no-execution invariant key
    present in the receipt.  A flag passes when the receipt value is False
    (or True for human_approval_required).
    """
    results: dict[str, bool] = {}
    for key in _MUST_BE_FALSE:
        if key in receipt:
            results[key] = (receipt[key] is False)
    # human_approval_required must be True if present
    if "human_approval_required" in receipt:
        results["human_approval_required"] = (receipt["human_approval_required"] is True)
    return results


def all_invariants_hold(receipt: dict[str, Any]) -> bool:
    """Return True iff every no-execution invariant in the receipt passes."""
    return all(check_no_execution_invariants(receipt).values())


# ─────────────────────────────────────────────────────────────────────────────
# Pretty-printer (only runs when the module is executed directly)
# ─────────────────────────────────────────────────────────────────────────────

def _hr(char: str = "─", width: int = 66) -> None:
    print(char * width)


def _section(title: str) -> None:
    _hr("═")
    print(f"  {title}")
    _hr("═")


def _field(label: str, value: Any, indent: int = 4) -> None:
    pad = " " * indent
    if isinstance(value, list):
        print(f"{pad}{label}: {value}")
    else:
        print(f"{pad}{label}: {value}")


def _print_invariants(receipt: dict[str, Any], label: str = "") -> None:
    inv = check_no_execution_invariants(receipt)
    prefix = f"  [{label}] " if label else "  "
    for k, v in inv.items():
        mark = "✓" if v else "✗"
        print(f"{prefix}{mark}  {k} = {receipt.get(k)}")


def run_demo(quiet: bool = False) -> dict[str, Any]:
    """
    Run all three scenarios.  If quiet=False, print a human-readable summary.
    Returns a dict with keys 'a', 'b', 'c' holding each scenario's result dict.
    """
    results: dict[str, Any] = {}

    # ── Scenario A ──────────────────────────────────────────────────────────
    a = scenario_a()
    results["a"] = a
    if not quiet:
        _section("Scenario A — Accepted advisory flow (Claude → propose_test_run)")
        _field("Intent decision",    a["intent_receipt"]["decision"])
        _field("Preflight decision", a["preflight_receipt"]["decision"])
        _field("Replay decision",    a["replay_receipt"]["decision"])
        _field("Scenario A ok",      a["ok"])
        print()
        print("  No-execution invariants (intent receipt):")
        _print_invariants(a["intent_receipt"], "intent")
        print("  No-execution invariants (preflight receipt):")
        _print_invariants(a["preflight_receipt"], "preflight")
        print("  No-execution invariants (replay receipt):")
        _print_invariants(a["replay_receipt"], "replay")
        print()
        _field("Intent receipt_hash   (first 16)",
               a["intent_receipt"]["receipt_hash"][:16] + "…")
        _field("Preflight receipt_hash (first 16)",
               a["preflight_receipt"]["receipt_hash"][:16] + "…")
        _field("Replay receipt_hash   (first 16)",
               a["replay_receipt"]["receipt_hash"][:16] + "…")
        print()

    # ── Scenario B ──────────────────────────────────────────────────────────
    b = scenario_b()
    results["b"] = b
    if not quiet:
        _section("Scenario B — Dangerous command denied (Codex → git push)")
        _field("Intent decision",    b["intent_receipt"]["decision"])
        _field("Preflight decision", b["preflight_receipt"]["decision"])
        _field("Reason codes",       b["preflight_receipt"]["reason_codes"])
        _field("Scenario B ok",      b["ok"])
        print()
        print("  No-execution invariants (preflight receipt despite denial):")
        _print_invariants(b["preflight_receipt"], "preflight")
        print()

    # ── Scenario C ──────────────────────────────────────────────────────────
    c = scenario_c()
    results["c"] = c
    if not quiet:
        _section("Scenario C — Tampered receipt denied by replay verifier")
        _field("Original preflight decision",     c["original_receipt"]["decision"])
        _field("Tampered real_authority_granted",  c["tampered_receipt"]["real_authority_granted"])
        _field("Tampered command_permitted",       c["tampered_receipt"]["command_permitted"])
        _field("Replay decision",                  c["replay_receipt"]["decision"])
        _field("Replay reason codes",              c["replay_receipt"]["reason_codes"])
        _field("Scenario C ok",                    c["ok"])
        print()
        print("  No-execution invariants (replay receipt catches tamper):")
        _print_invariants(c["replay_receipt"], "replay")
        print()

    if not quiet:
        _hr("═")
        all_ok = a["ok"] and b["ok"] and c["ok"]
        status = "ALL SCENARIOS PASSED" if all_ok else "SOME SCENARIOS FAILED"
        print(f"  {status}")
        print()
        print(textwrap.dedent("""\
          PFC boundary summary
          ────────────────────
          External coding agents can propose intent, PFC can preflight it,
          and receipts can be replay-verified without granting execution
          authority.  command_executed, command_permitted, and
          real_authority_granted remain False throughout.
        """))
        _hr("═")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    quiet = "--quiet" in sys.argv
    result = run_demo(quiet=quiet)
    all_ok = result["a"]["ok"] and result["b"]["ok"] and result["c"]["ok"]
    sys.exit(0 if all_ok else 1)
