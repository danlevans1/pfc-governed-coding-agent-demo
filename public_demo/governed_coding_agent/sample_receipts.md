# Sample Receipts

> These receipts are the **actual output** of running
> `python -m examples.governed_coding_agent_demo` against the live codebase.
> Hashes are deterministic: running the demo again produces identical values.
>
> **Advisory / simulation-only.** No receipt here represents permission to
> execute anything.

---

## Scenario A — Accepted advisory flow

### Console output

```
══════════════════════════════════════════════════════════════════
  Scenario A — Accepted advisory flow (Claude → propose_test_run)
══════════════════════════════════════════════════════════════════
    Intent decision: INTENT_ADVISORY_ACCEPTED
    Preflight decision: PREFLIGHT_ADVISORY_ACCEPTED
    Replay decision: REPLAY_VERIFIED
    Scenario A ok: True

  No-execution invariants (intent receipt):
  [intent] ✓  execution_performed = False
  [intent] ✓  real_authority_granted = False
  [intent] ✓  git_push_performed = False
  [intent] ✓  deployment_performed = False
  [intent] ✓  network_call_performed = False
  [intent] ✓  credential_access_performed = False
  No-execution invariants (preflight receipt):
  [preflight] ✓  command_executed = False
  [preflight] ✓  command_permitted = False
  [preflight] ✓  real_authority_granted = False
  [preflight] ✓  git_push_performed = False
  [preflight] ✓  deployment_performed = False
  [preflight] ✓  network_call_performed = False
  [preflight] ✓  credential_access_performed = False
  [preflight] ✓  human_approval_required = True
  No-execution invariants (replay receipt):
  [replay] ✓  execution_performed = False
  [replay] ✓  command_executed = False
  [replay] ✓  command_permitted = False
  [replay] ✓  real_authority_granted = False
  [replay] ✓  git_push_performed = False
  [replay] ✓  deployment_performed = False
  [replay] ✓  network_call_performed = False
  [replay] ✓  credential_access_performed = False

    Intent receipt_hash   (first 16): 6f9a5c18b787a352…
    Preflight receipt_hash (first 16): 2697d5d9295a1fd0…
    Replay receipt_hash   (first 16): b8009fa33aa7fb3a…
```

### Intent receipt (full JSON)

```json
{
  "intent_id": "demo-intent-A-001",
  "agent_id": "claude-agent-demo",
  "agent_type": "claude",
  "requested_action": "propose_test_run",
  "target_path": "tests/test_sample.py",
  "scope": {
    "context": "demo – scenario A"
  },
  "risk_level": "low",
  "human_review_required": true,
  "decision": "INTENT_ADVISORY_ACCEPTED",
  "checks": {
    "intent_id_present": true,
    "agent_id_present": true,
    "agent_type_present": true,
    "advisory_only_set": true,
    "human_review_required_set": true,
    "action_allowed": true,
    "risk_within_bound": true,
    "path_safe": true
  },
  "reason_codes": [],
  "execution_performed": false,
  "execution_permitted": false,
  "real_authority_granted": false,
  "git_push_performed": false,
  "deployment_performed": false,
  "network_call_performed": false,
  "credential_access_performed": false,
  "advisory_only": true,
  "receipt_hash": "6f9a5c18b787a352a4dcf125b4876c67393f902bbec85c550ce289f4f4b111a5"
}
```

**Reading this receipt:**
- `decision: INTENT_ADVISORY_ACCEPTED` — the intent passes all governance checks.
- `checks` — every predicate is `true`, producing an empty `reason_codes` list.
- Every execution flag is `false`; `advisory_only` is `true`.
- `receipt_hash` — SHA-256 over all fields above.  Feeds into the preflight layer
  as `parent_intent_receipt_hash`.

---

### Preflight receipt (full JSON)

```json
{
  "preflight_id": "demo-preflight-A-001",
  "parent_intent_id": "demo-intent-A-001",
  "parent_agent_id": "claude-agent-demo",
  "parent_agent_type": "claude",
  "parent_intent_receipt_hash": "6f9a5c18b787a352a4dcf125b4876c67393f902bbec85c550ce289f4f4b111a5",
  "proposed_command": "pytest tests/test_sample.py -v",
  "command_type": "run_focused_tests",
  "target_paths": [
    "tests/test_sample.py"
  ],
  "decision": "PREFLIGHT_ADVISORY_ACCEPTED",
  "checks": {
    "parent_intent_accepted": true,
    "parent_receipt_hash_valid": true,
    "intent_revalidation_passed": true,
    "requires_human_approval_set": true,
    "command_type_allowed": true,
    "command_safe": true,
    "all_paths_safe": true
  },
  "reason_codes": [],
  "command_executed": false,
  "command_permitted": false,
  "real_authority_granted": false,
  "human_approval_required": true,
  "git_push_performed": false,
  "deployment_performed": false,
  "network_call_performed": false,
  "credential_access_performed": false,
  "receipt_hash": "2697d5d9295a1fd04e50755bdead220c5cfe03cf6351ed7bcc4d90d24c054335"
}
```

**Reading this receipt:**
- `parent_intent_receipt_hash` links this receipt back to the intent receipt above.
- `command_executed: false` — the command was never run.
- `command_permitted: false` — no execution permission was granted.
- `human_approval_required: true` — structural invariant; cannot be overridden.

---

### Replay verification receipt (full JSON)

```json
{
  "preflight_id": "demo-preflight-A-001",
  "stored_receipt_hash": "2697d5d9295a1fd04e50755bdead220c5cfe03cf6351ed7bcc4d90d24c054335",
  "recomputed_receipt_hash": "2697d5d9295a1fd04e50755bdead220c5cfe03cf6351ed7bcc4d90d24c054335",
  "decision": "REPLAY_VERIFIED",
  "replay_checks": {
    "stored_receipt_present": true,
    "stored_command_executed_false": true,
    "stored_command_permitted_false": true,
    "stored_real_authority_granted_false": true,
    "field_decision_matches": true,
    "field_reason_codes_matches": true,
    "field_command_type_matches": true,
    "field_target_paths_matches": true,
    "field_parent_intent_receipt_hash_matches": true,
    "field_command_executed_matches": true,
    "field_command_permitted_matches": true,
    "field_real_authority_granted_matches": true,
    "field_human_approval_required_matches": true,
    "field_receipt_hash_matches": true,
    "prev_preflight_receipt_hash_matches": true
  },
  "reason_codes": [],
  "command_executed": false,
  "command_permitted": false,
  "real_authority_granted": false,
  "execution_performed": false,
  "git_push_performed": false,
  "deployment_performed": false,
  "network_call_performed": false,
  "credential_access_performed": false,
  "receipt_hash": "b8009fa33aa7fb3a73d03291889471040081238392b1e0d7fdb980a3050c1e89"
}
```

**Reading this receipt:**
- `stored_receipt_hash == recomputed_receipt_hash` — the preflight receipt is
  authentic; it was not tampered with after being issued.
- All 15 `replay_checks` are `true`.
- The replay receipt itself carries the same no-execution invariants.

---

## Scenario B — Dangerous command denied

### Console output

```
══════════════════════════════════════════════════════════════════
  Scenario B — Dangerous command denied (Codex → git push)
══════════════════════════════════════════════════════════════════
    Intent decision: INTENT_ADVISORY_ACCEPTED
    Preflight decision: DENY
    Reason codes: ['COMMAND_DENIED']
    Scenario B ok: True

  No-execution invariants (preflight receipt despite denial):
  [preflight] ✓  command_executed = False
  [preflight] ✓  command_permitted = False
  [preflight] ✓  real_authority_granted = False
  [preflight] ✓  git_push_performed = False
  [preflight] ✓  deployment_performed = False
  [preflight] ✓  network_call_performed = False
  [preflight] ✓  credential_access_performed = False
  [preflight] ✓  human_approval_required = True
```

**Key observation:** The Codex intent itself was `INTENT_ADVISORY_ACCEPTED` —
it was well-formed.  The denial fires at the preflight layer because
`git push origin main` matches the deny-list.  No execution flags change.

---

## Scenario C — Tampered receipt denied

### Console output

```
══════════════════════════════════════════════════════════════════
  Scenario C — Tampered receipt denied by replay verifier
══════════════════════════════════════════════════════════════════
    Original preflight decision: PREFLIGHT_ADVISORY_ACCEPTED
    Tampered real_authority_granted: True
    Tampered command_permitted: True
    Replay decision: DENY
    Replay reason codes: ['COMMAND_PERMITTED_FLAG_MISMATCH',
                          'REAL_AUTHORITY_GRANTED_FLAG_MISMATCH',
                          'RECEIPT_HASH_MISMATCH',
                          'STORED_RECEIPT_CLAIMS_COMMAND_PERMITTED',
                          'STORED_RECEIPT_CLAIMS_REAL_AUTHORITY_GRANTED']
    Scenario C ok: True

  No-execution invariants (replay receipt catches tamper):
  [replay] ✓  execution_performed = False
  [replay] ✓  command_executed = False
  [replay] ✓  command_permitted = False
  [replay] ✓  real_authority_granted = False
  [replay] ✓  git_push_performed = False
  [replay] ✓  deployment_performed = False
  [replay] ✓  network_call_performed = False
  [replay] ✓  credential_access_performed = False
```

**Key observation:** Five distinct reason codes are reported.  Even after
catching `STORED_RECEIPT_CLAIMS_REAL_AUTHORITY_GRANTED`, the replay receipt
itself carries `real_authority_granted=False`.  The verifier does not inherit
the tamper it detects.

---

## Final summary line

```
══════════════════════════════════════════════════════════════════
  ALL SCENARIOS PASSED

PFC boundary summary
────────────────────
External coding agents can propose intent, PFC can preflight it,
and receipts can be replay-verified without granting execution
authority.  command_executed, command_permitted, and
real_authority_granted remain False throughout.
══════════════════════════════════════════════════════════════════
```
