# Demo Flow — Annotated Walkthrough

> **Advisory / simulation-only.**  No commands are executed at any step.

The demo (`examples/governed_coding_agent_demo.py`) runs three scenarios.
Each scenario is fully deterministic: given the same inputs, the same receipt
hashes are always produced.

---

## Scenario A — Accepted advisory flow

**Who:** Claude agent proposing a test run.  
**Outcome:** Full chain accepted — `INTENT_ADVISORY_ACCEPTED` →
`PREFLIGHT_ADVISORY_ACCEPTED` → `REPLAY_VERIFIED`.

### Step 1 — Build the intent

```python
intent = {
    "intent_id":             "demo-intent-A-001",
    "agent_id":              "claude-agent-demo",
    "agent_type":            "claude",
    "requested_action":      "propose_test_run",   # allowed advisory verb
    "target_path":           "tests/test_sample.py",
    "scope":                 {"context": "demo – scenario A"},
    "risk_level":            "low",                # ≤ bounded
    "human_review_required": True,                 # must be True
    "advisory_only":         True,                 # must be True
}
```

All eight governance checks pass:

| Check | Result |
|---|---|
| `intent_id_present` | ✓ |
| `agent_id_present` | ✓ |
| `agent_type_present` | ✓ |
| `advisory_only_set` | ✓ (`True`, not `"true"` or `1`) |
| `human_review_required_set` | ✓ (`True`) |
| `action_allowed` | ✓ (`propose_test_run` ∈ allowed set) |
| `risk_within_bound` | ✓ (`low` ≤ `bounded`) |
| `path_safe` | ✓ (repo-relative, no sensitive segments) |

**Decision:** `INTENT_ADVISORY_ACCEPTED`

The intent receipt is SHA-256 hashed.  That hash is the `parent_intent_receipt_hash`
required by the next layer.

### Step 2 — Build the preflight request

```python
preflight_request = {
    "preflight_id":                "demo-preflight-A-001",
    "proposed_command":            "pytest tests/test_sample.py -v",
    "command_type":                "run_focused_tests",   # allowed simulated type
    "target_paths":                ["tests/test_sample.py"],
    "requires_human_approval":     True,
    "parent_intent_receipt_hash":  <intent_receipt["receipt_hash"]>,
}
```

Seven preflight checks are applied:

| Check | Result |
|---|---|
| `parent_intent_accepted` | ✓ (parent decision == `INTENT_ADVISORY_ACCEPTED`) |
| `parent_receipt_hash_valid` | ✓ (hash matches stored receipt) |
| `intent_revalidation_passed` | ✓ (intent re-validated inline) |
| `requires_human_approval_set` | ✓ (`True`) |
| `command_type_allowed` | ✓ (`run_focused_tests` ∈ allowed set) |
| `command_safe` | ✓ (`pytest …` matches no denied-command pattern) |
| `all_paths_safe` | ✓ (`tests/test_sample.py` is repo-relative and safe) |

**Decision:** `PREFLIGHT_ADVISORY_ACCEPTED`

> `command_executed = False`  
> `command_permitted = False`  
> These are structural invariants, not side effects of the decision.

### Step 3 — Replay verification

The verifier independently recomputes the preflight receipt from the original
raw inputs and compares every material field to the stored receipt:

```
Checked fields
──────────────
decision                      stored == recomputed  ✓
reason_codes                  stored == recomputed  ✓
command_type                  stored == recomputed  ✓
target_paths                  stored == recomputed  ✓
parent_intent_receipt_hash    stored == recomputed  ✓
command_executed              stored == recomputed  ✓
command_permitted             stored == recomputed  ✓
real_authority_granted        stored == recomputed  ✓
human_approval_required       stored == recomputed  ✓
receipt_hash                  stored == recomputed  ✓  ← terminal integrity check
prev_preflight_receipt_hash   (absent in both)      ✓
```

**Decision:** `REPLAY_VERIFIED`

`stored_receipt_hash == recomputed_receipt_hash` — the receipt is authentic.

---

## Scenario B — Dangerous command denied

**Who:** Codex agent proposing a `git push`.  
**Outcome:** Intent is accepted; preflight is denied because the proposed
command is on the deny-list.

### The intent

```python
intent = {
    "intent_id":             "demo-intent-B-001",
    "agent_id":              "codex-agent-demo",
    "agent_type":            "codex",
    "requested_action":      "propose_commit",   # valid advisory verb
    "risk_level":            "bounded",          # at the limit, still allowed
    "human_review_required": True,
    "advisory_only":         True,
    ...
}
```

**Intent decision:** `INTENT_ADVISORY_ACCEPTED` — the intent is well-formed.

### The dangerous preflight request

```python
proposed_command = "git push origin main"
```

The preflight deny-list pattern for git mutations matches:

```
\bgit\s+(push|merge|rebase|reset|clean|rm|…)\b
```

**Preflight decision:** `DENY`  
**Reason codes:** `["COMMAND_DENIED"]`

Despite the denial, the receipt still carries:

```
command_executed        = False
command_permitted       = False
real_authority_granted  = False
human_approval_required = True
```

The denial is a governance record, not execution.

### Denied command categories

The deny-list covers all of these (illustrative, not exhaustive):

| Category | Examples |
|---|---|
| Git mutations | `git push`, `git merge`, `git rebase`, `git reset`, `git clean` |
| Deploy / release | `deploy`, `kubectl apply`, `helm upgrade`, `terraform apply/destroy` |
| Registry publish | `npm publish`, `twine upload`, `docker push` |
| Network / remote | `curl`, `wget`, `ssh`, `scp`, `rsync` |
| Privilege escalation | `sudo`, `su`, `doas` |
| File permission mutation | `chmod`, `chown`, `chgrp` |
| Destructive file ops | `rm -rf`, `shred`, `dd if=` |
| Secret / credential access | `aws secretsmanager`, `vault read`, `az keyvault` |
| Production-targeting flags | `--env prod`, `--environment production` |

---

## Scenario C — Tampered receipt denied by replay verifier

**Who:** An attacker (or bug) that modifies a stored receipt to claim authority
after the fact.  
**Outcome:** Replay verification catches all tampers and returns `DENY`.

### The tamper

Starting from a valid `PREFLIGHT_ADVISORY_ACCEPTED` receipt:

```python
tampered_receipt = dict(original_receipt)
tampered_receipt["real_authority_granted"] = True   # ← tamper
tampered_receipt["command_permitted"]       = True   # ← tamper
tampered_receipt["receipt_hash"]            = "00" * 32  # ← corrupted hash
```

### What the replay verifier catches

The verifier re-runs the preflight evaluator from the original raw inputs.
The recomputed receipt has `real_authority_granted=False` and
`command_permitted=False`.  Field comparison detects all mismatches:

| Reason code | What it means |
|---|---|
| `STORED_RECEIPT_CLAIMS_REAL_AUTHORITY_GRANTED` | Pre-check: stored receipt explicitly asserts forbidden flag |
| `STORED_RECEIPT_CLAIMS_COMMAND_PERMITTED` | Pre-check: stored receipt explicitly asserts forbidden flag |
| `REAL_AUTHORITY_GRANTED_FLAG_MISMATCH` | Field comparison: stored ≠ recomputed |
| `COMMAND_PERMITTED_FLAG_MISMATCH` | Field comparison: stored ≠ recomputed |
| `RECEIPT_HASH_MISMATCH` | Terminal: stored hash ≠ recomputed hash |

**Replay decision:** `DENY`

The replay receipt itself still carries `real_authority_granted=False` and
`command_executed=False` — the verifier never grants what it is checking for.

---

## Receipt hash chain

Each receipt is SHA-256 hashed over all its fields (excluding the hash itself,
which is appended last).  Hashes can be chained:

```
intent_receipt.receipt_hash
    ↓ embedded as parent_intent_receipt_hash
preflight_receipt.receipt_hash
    ↓ can be embedded as prev_preflight_receipt_hash in the next preflight
preflight_receipt_2.receipt_hash
    ↓
…
```

The replay verifier checks that `stored.receipt_hash == recomputed.receipt_hash`,
which means every field that feeds into the hash must also match.

---

## What never happens

At no point in any scenario does the system:

- Run a shell command
- Write to or read from the file system beyond module loading
- Make a network request
- Access environment variables containing secrets
- Read credential files
- Push to a Git remote
- Deploy or restart any service
- Modify any database or state store
- Grant itself or any agent elevated privileges
- Activate execution authority
