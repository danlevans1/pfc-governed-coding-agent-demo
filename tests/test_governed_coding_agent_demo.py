"""
Tests for examples/governed_coding_agent_demo.py

Proves that:
  - the demo module imports cleanly
  - scenario_a() returns INTENT_ADVISORY_ACCEPTED, PREFLIGHT_ADVISORY_ACCEPTED,
    and REPLAY_VERIFIED
  - scenario_b() returns DENY on the preflight with COMMAND_DENIED
  - scenario_c() returns DENY on the replay with tamper-detection reason codes
  - all returned receipts preserve no-execution / no-authority invariants
  - run_demo() runs without error in both normal and quiet modes
  - the 'ok' boolean on each scenario is True
  - receipts include issued_at / expires_at / ttl_seconds freshness fields
  - a valid non-expired receipt still verifies as REPLAY_VERIFIED
  - an expired receipt returns DENY with RECEIPT_EXPIRED
  - no execution/authority flags are ever True
"""

import importlib

import pytest

from src.governed_coding_agent_intent import (
    INTENT_ADVISORY_ACCEPTED,
    DEMO_ISSUED_AT,
    DEMO_TTL_SECONDS,
    DEMO_EXPIRES_AT,
    DEMO_CHECK_AT,
)
from src.governed_coding_agent_preflight import PREFLIGHT_ADVISORY_ACCEPTED
from src.governed_coding_agent_preflight_replay import (
    REPLAY_VERIFIED,
    verify_preflight_replay,
)
from src.governance_decision import DENY

# Import the demo module
from examples.governed_coding_agent_demo import (
    all_invariants_hold,
    check_no_execution_invariants,
    run_demo,
    scenario_a,
    scenario_b,
    scenario_c,
)

# ── no-execution invariant keys ────────────────────────────────────────────
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


# ── helpers ────────────────────────────────────────────────────────────────

def _assert_no_execution(receipt: dict, label: str = "") -> None:
    """Assert every present no-execution flag holds its invariant value."""
    tag = f" [{label}]" if label else ""
    for key in _MUST_BE_FALSE:
        if key in receipt:
            assert receipt[key] is False, (
                f"Invariant violation{tag}: {key!r} should be False, got {receipt[key]!r}"
            )
    if "human_approval_required" in receipt:
        assert receipt["human_approval_required"] is True, (
            f"Invariant violation{tag}: human_approval_required should be True"
        )


# ── 1. Module imports cleanly ─────────────────────────────────────────────

class TestModuleImport:
    def test_demo_module_imports(self):
        import examples.governed_coding_agent_demo as demo
        assert hasattr(demo, "scenario_a")
        assert hasattr(demo, "scenario_b")
        assert hasattr(demo, "scenario_c")
        assert hasattr(demo, "run_demo")
        assert hasattr(demo, "all_invariants_hold")
        assert hasattr(demo, "check_no_execution_invariants")

    def test_importlib_reload_works(self):
        import examples.governed_coding_agent_demo as demo
        reloaded = importlib.reload(demo)
        assert reloaded is not None


# ── 2. Scenario A — accepted advisory flow ────────────────────────────────

class TestScenarioA:
    def setup_method(self):
        self.result = scenario_a()

    def test_ok_flag_is_true(self):
        assert self.result["ok"] is True

    def test_intent_receipt_is_accepted(self):
        assert self.result["intent_receipt"]["decision"] == INTENT_ADVISORY_ACCEPTED

    def test_preflight_receipt_is_accepted(self):
        assert self.result["preflight_receipt"]["decision"] == PREFLIGHT_ADVISORY_ACCEPTED

    def test_replay_receipt_is_verified(self):
        assert self.result["replay_receipt"]["decision"] == REPLAY_VERIFIED

    def test_intent_is_claude_agent(self):
        assert self.result["intent"]["agent_type"] == "claude"

    def test_intent_action_is_propose_test_run(self):
        assert self.result["intent"]["requested_action"] == "propose_test_run"

    def test_command_type_is_run_focused_tests(self):
        assert self.result["preflight_receipt"]["command_type"] == "run_focused_tests"

    def test_parent_hash_linked(self):
        """Preflight receipt links back to intent receipt hash."""
        assert (
            self.result["preflight_receipt"]["parent_intent_receipt_hash"]
            == self.result["intent_receipt"]["receipt_hash"]
        )

    def test_replay_stored_and_recomputed_hashes_match(self):
        r = self.result["replay_receipt"]
        assert r["stored_receipt_hash"] == r["recomputed_receipt_hash"]

    def test_intent_receipt_no_execution_invariants(self):
        _assert_no_execution(self.result["intent_receipt"], "intent")

    def test_preflight_receipt_no_execution_invariants(self):
        _assert_no_execution(self.result["preflight_receipt"], "preflight")

    def test_replay_receipt_no_execution_invariants(self):
        _assert_no_execution(self.result["replay_receipt"], "replay")

    def test_all_invariants_hold_helper(self):
        for key in ("intent_receipt", "preflight_receipt", "replay_receipt"):
            assert all_invariants_hold(self.result[key]), (
                f"all_invariants_hold failed for {key}"
            )

    def test_receipts_have_hashes(self):
        for key in ("intent_receipt", "preflight_receipt", "replay_receipt"):
            h = self.result[key]["receipt_hash"]
            assert isinstance(h, str) and len(h) == 64, (
                f"{key} receipt_hash should be a 64-char hex string"
            )

    def test_scenario_a_is_deterministic(self):
        """Running scenario_a twice produces identical receipt hashes."""
        r1 = scenario_a()
        r2 = scenario_a()
        assert r1["intent_receipt"]["receipt_hash"]    == r2["intent_receipt"]["receipt_hash"]
        assert r1["preflight_receipt"]["receipt_hash"] == r2["preflight_receipt"]["receipt_hash"]
        assert r1["replay_receipt"]["receipt_hash"]    == r2["replay_receipt"]["receipt_hash"]


# ── 3. Scenario B — dangerous command denied ─────────────────────────────

class TestScenarioB:
    def setup_method(self):
        self.result = scenario_b()

    def test_ok_flag_is_true(self):
        assert self.result["ok"] is True

    def test_intent_is_codex_agent(self):
        assert self.result["intent"]["agent_type"] == "codex"

    def test_intent_receipt_is_accepted(self):
        assert self.result["intent_receipt"]["decision"] == INTENT_ADVISORY_ACCEPTED

    def test_preflight_is_denied(self):
        assert self.result["preflight_receipt"]["decision"] == DENY

    def test_command_denied_reason_code_present(self):
        assert "COMMAND_DENIED" in self.result["preflight_receipt"]["reason_codes"]

    def test_dangerous_command_is_git_push(self):
        assert "git push" in self.result["preflight_receipt"]["proposed_command"]

    def test_preflight_receipt_no_execution_invariants(self):
        """Even a denied preflight must preserve no-execution flags."""
        _assert_no_execution(self.result["preflight_receipt"], "denied-preflight")

    def test_intent_receipt_no_execution_invariants(self):
        _assert_no_execution(self.result["intent_receipt"], "intent")

    def test_command_executed_false_despite_denial(self):
        assert self.result["preflight_receipt"]["command_executed"] is False

    def test_command_permitted_false_despite_denial(self):
        assert self.result["preflight_receipt"]["command_permitted"] is False

    def test_real_authority_granted_false_despite_denial(self):
        assert self.result["preflight_receipt"]["real_authority_granted"] is False


# ── 4. Scenario C — tampered receipt denied by replay ────────────────────

class TestScenarioC:
    def setup_method(self):
        self.result = scenario_c()

    def test_ok_flag_is_true(self):
        assert self.result["ok"] is True

    def test_original_receipt_was_accepted(self):
        assert self.result["original_receipt"]["decision"] == PREFLIGHT_ADVISORY_ACCEPTED

    def test_replay_is_denied(self):
        assert self.result["replay_receipt"]["decision"] == DENY

    def test_tamper_detection_real_authority_granted(self):
        assert (
            "STORED_RECEIPT_CLAIMS_REAL_AUTHORITY_GRANTED"
            in self.result["replay_receipt"]["reason_codes"]
        )

    def test_tamper_detection_command_permitted(self):
        assert (
            "STORED_RECEIPT_CLAIMS_COMMAND_PERMITTED"
            in self.result["replay_receipt"]["reason_codes"]
        )

    def test_tamper_detection_hash_mismatch(self):
        assert (
            "RECEIPT_HASH_MISMATCH"
            in self.result["replay_receipt"]["reason_codes"]
        )

    def test_tampered_receipt_claimed_authority(self):
        assert self.result["tampered_receipt"]["real_authority_granted"] is True

    def test_replay_receipt_no_execution_invariants(self):
        """The replay verifier itself must preserve no-execution invariants."""
        _assert_no_execution(self.result["replay_receipt"], "replay")

    def test_replay_command_executed_false(self):
        assert self.result["replay_receipt"]["command_executed"] is False

    def test_replay_real_authority_granted_false(self):
        assert self.result["replay_receipt"]["real_authority_granted"] is False


# ── 5. run_demo() integration ─────────────────────────────────────────────

class TestRunDemo:
    def test_run_demo_quiet_succeeds(self):
        result = run_demo(quiet=True)
        assert isinstance(result, dict)
        assert set(result.keys()) == {"a", "b", "c"}

    def test_run_demo_all_scenarios_ok(self):
        result = run_demo(quiet=True)
        assert result["a"]["ok"] is True
        assert result["b"]["ok"] is True
        assert result["c"]["ok"] is True

    def test_run_demo_pretty_print_no_exception(self, capsys):
        run_demo(quiet=False)
        out = capsys.readouterr().out
        assert "SCENARIO A" in out.upper() or "Scenario A" in out
        assert "Scenario B" in out
        assert "Scenario C" in out
        assert "REPLAY_VERIFIED" in out or "REPLAY VERIFIED" in out.upper()

    def test_run_demo_returns_deterministic_results(self):
        r1 = run_demo(quiet=True)
        r2 = run_demo(quiet=True)
        assert (
            r1["a"]["intent_receipt"]["receipt_hash"]
            == r2["a"]["intent_receipt"]["receipt_hash"]
        )
        assert (
            r1["a"]["preflight_receipt"]["receipt_hash"]
            == r2["a"]["preflight_receipt"]["receipt_hash"]
        )


# ── 6. check_no_execution_invariants helper ───────────────────────────────

class TestCheckNoExecutionInvariantsHelper:
    def test_clean_receipt_all_true(self):
        clean = {
            "command_executed": False,
            "command_permitted": False,
            "real_authority_granted": False,
            "execution_performed": False,
        }
        checks = check_no_execution_invariants(clean)
        assert all(checks.values())

    def test_violated_receipt_reports_false(self):
        bad = {
            "command_executed": True,
            "real_authority_granted": True,
        }
        checks = check_no_execution_invariants(bad)
        assert checks["command_executed"] is False
        assert checks["real_authority_granted"] is False

    def test_all_invariants_hold_true_for_clean_dict(self):
        clean = {"command_executed": False, "real_authority_granted": False}
        assert all_invariants_hold(clean) is True

    def test_all_invariants_hold_false_for_dirty_dict(self):
        dirty = {"command_executed": True}
        assert all_invariants_hold(dirty) is False


# ── 7. Receipt freshness fields and expiry verification ───────────────────

# Fixed check times used only in this class, relative to DEMO_EXPIRES_AT
# ("2026-05-26T01:00:00Z"):
#   _CHECK_WITHIN_TTL  — 30 min after issuance; well within window
#   _CHECK_AFTER_EXPIRY — 1 hr past expiry; clearly expired
_CHECK_WITHIN_TTL   = DEMO_CHECK_AT         # "2026-05-26T00:30:00Z"
_CHECK_AFTER_EXPIRY = "2026-05-26T02:00:00Z"


class TestReceiptFreshness:
    """
    Proves:
      - intent and preflight receipts carry issued_at / expires_at / ttl_seconds
      - freshness field values match the expected demo constants
      - a valid, non-expired receipt verifies as REPLAY_VERIFIED
      - an expired receipt is denied with RECEIPT_EXPIRED
      - no execution / authority flags are ever True on any receipt
    """

    def setup_method(self):
        self.a = scenario_a()
        self.intent_receipt    = self.a["intent_receipt"]
        self.preflight_receipt = self.a["preflight_receipt"]
        self.intent            = self.a["intent"]
        self.intent_receipt_   = self.a["intent_receipt"]
        self.preflight_request = self.a["preflight_request"]

    # ── freshness fields present ─────────────────────────────────────────────

    def test_intent_receipt_has_issued_at(self):
        assert "issued_at" in self.intent_receipt

    def test_intent_receipt_has_expires_at(self):
        assert "expires_at" in self.intent_receipt

    def test_intent_receipt_has_ttl_seconds(self):
        assert "ttl_seconds" in self.intent_receipt

    def test_preflight_receipt_has_issued_at(self):
        assert "issued_at" in self.preflight_receipt

    def test_preflight_receipt_has_expires_at(self):
        assert "expires_at" in self.preflight_receipt

    def test_preflight_receipt_has_ttl_seconds(self):
        assert "ttl_seconds" in self.preflight_receipt

    # ── freshness field values match demo constants ──────────────────────────

    def test_intent_receipt_issued_at_value(self):
        assert self.intent_receipt["issued_at"] == DEMO_ISSUED_AT

    def test_intent_receipt_expires_at_value(self):
        assert self.intent_receipt["expires_at"] == DEMO_EXPIRES_AT

    def test_intent_receipt_ttl_seconds_value(self):
        assert self.intent_receipt["ttl_seconds"] == DEMO_TTL_SECONDS

    def test_preflight_receipt_issued_at_value(self):
        assert self.preflight_receipt["issued_at"] == DEMO_ISSUED_AT

    def test_preflight_receipt_expires_at_value(self):
        assert self.preflight_receipt["expires_at"] == DEMO_EXPIRES_AT

    def test_preflight_receipt_ttl_seconds_value(self):
        assert self.preflight_receipt["ttl_seconds"] == DEMO_TTL_SECONDS

    # ── demo check_at is within TTL (sanity) ────────────────────────────────

    def test_demo_check_at_is_before_expires_at(self):
        """DEMO_CHECK_AT must be within the TTL window for the happy path."""
        assert DEMO_CHECK_AT < DEMO_EXPIRES_AT

    def test_demo_check_at_is_after_issued_at(self):
        assert DEMO_ISSUED_AT < DEMO_CHECK_AT

    # ── valid non-expired receipt verifies ───────────────────────────────────

    def test_valid_non_expired_receipt_verifies(self):
        """Replay verification with check_at within the TTL returns REPLAY_VERIFIED."""
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_WITHIN_TTL,
        )
        assert replay["decision"] == REPLAY_VERIFIED

    def test_valid_receipt_has_no_receipt_expired_code(self):
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_WITHIN_TTL,
        )
        assert "RECEIPT_EXPIRED" not in replay["reason_codes"]

    def test_valid_receipt_not_expired_check_is_true(self):
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_WITHIN_TTL,
        )
        assert replay["replay_checks"]["receipt_not_expired"] is True

    # ── expired receipt returns DENY ─────────────────────────────────────────

    def test_expired_receipt_returns_deny(self):
        """Replay verification with check_at after expires_at returns DENY."""
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_AFTER_EXPIRY,
        )
        assert replay["decision"] == DENY

    def test_expired_receipt_has_receipt_expired_reason_code(self):
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_AFTER_EXPIRY,
        )
        assert "RECEIPT_EXPIRED" in replay["reason_codes"]

    def test_expired_receipt_not_expired_check_is_false(self):
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_AFTER_EXPIRY,
        )
        assert replay["replay_checks"]["receipt_not_expired"] is False

    # ── check_at recorded in replay receipt ──────────────────────────────────

    def test_replay_receipt_records_check_at(self):
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_WITHIN_TTL,
        )
        assert replay["check_at"] == _CHECK_WITHIN_TTL

    # ── no execution/authority flags ever True ───────────────────────────────

    def test_no_execution_flags_false_on_intent_receipt(self):
        _assert_no_execution(self.intent_receipt, "intent-freshness")

    def test_no_execution_flags_false_on_preflight_receipt(self):
        _assert_no_execution(self.preflight_receipt, "preflight-freshness")

    def test_no_execution_flags_false_on_valid_replay(self):
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_WITHIN_TTL,
        )
        _assert_no_execution(replay, "replay-valid")

    def test_no_execution_flags_false_on_expired_deny(self):
        """Even an expired DENY replay preserves all no-execution invariants."""
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_AFTER_EXPIRY,
        )
        _assert_no_execution(replay, "replay-expired")

    def test_real_authority_granted_false_on_expired_deny(self):
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_AFTER_EXPIRY,
        )
        assert replay["real_authority_granted"] is False

    def test_command_executed_false_on_expired_deny(self):
        replay = verify_preflight_replay(
            coding_agent_intent=self.intent,
            parent_intent_receipt=self.intent_receipt_,
            preflight_request=self.preflight_request,
            stored_preflight_receipt=self.preflight_receipt,
            check_at=_CHECK_AFTER_EXPIRY,
        )
        assert replay["command_executed"] is False
