# Safety Boundaries

> This document is a comprehensive reference for the safety guarantees
> maintained throughout the governed coding-agent proof chain.
>
> **Advisory / simulation-only.** Every statement here is proven by the
> deterministic test suite.  Nothing here describes future execution authority.

---

## The core principle

> **PFC is the execution boundary.**
>
> External coding agents (Claude, Codex, or any advisory agent) can *propose*
> intent.  They cannot *execute* it.  No receipt, no decision token, and no
> governance check result grants execution authority.

---

## Layer-by-layer boundaries

### Layer 1 — Intent adapter (`governed_coding_agent_intent`)

**What it accepts:**

| Field | Constraint |
|---|---|
| `advisory_only` | Must be strictly `True` (boolean). `"true"`, `1`, or `None` are rejected. |
| `human_review_required` | Must be strictly `True` (boolean). |
| `requested_action` | Must be one of: `propose_file_change`, `propose_test_run`, `propose_commit`. No other string is accepted. |
| `risk_level` | Must be `"low"` or `"bounded"`. `"high"` and `"critical"` are rejected. |
| `target_path` | Must be a non-empty, repo-relative string. Absolute paths are rejected. `..` traversal is rejected. |

**What `target_path` must not contain:**

| Pattern | Examples rejected |
|---|---|
| Path traversal | `../escape`, `src/../../etc/passwd` |
| `.env` files | `.env`, `config/.env.production` |
| Secrets directories | `secrets/api_key.txt` |
| Credentials directories | `credentials/aws.json` |
| Deploy directories/scripts | `deploy/prod.sh`, `deployment/` |
| Production directories | `production/config.yaml`, `prod/` |
| Private key extensions | `*.pem`, `*.key`, `*.crt`, `*.p12`, `*.pfx` |
| SSH key filenames | `id_rsa`, `id_ed25519`, `authorized_keys` |
| Infra-as-code directories | `terraform/`, `ansible/`, `k8s/`, `kubernetes/` |
| CI/CD pipeline files | `.github/`, `.gitlab/`, `.circleci/` |

**Structural invariants on every intent receipt (regardless of decision):**

```
execution_performed        = False
execution_permitted        = False
real_authority_granted     = False
git_push_performed         = False
deployment_performed       = False
network_call_performed     = False
credential_access_performed= False
advisory_only              = True   (on the receipt itself)
```

---

### Layer 2 — Preflight wrapper (`governed_coding_agent_preflight`)

**Additional checks beyond intent re-validation:**

| Check | Requirement |
|---|---|
| Parent intent receipt | Must carry `INTENT_ADVISORY_ACCEPTED` + correct invariant flags |
| Parent receipt hash | Caller must supply the exact `receipt_hash` from the parent receipt; mismatch → `DENY` |
| Intent re-validation | Intent is re-validated inline regardless of parent decision |
| `requires_human_approval` | Must be strictly `True` |
| `command_type` | Must be one of: `inspect_diff`, `run_focused_tests`, `propose_commit` |
| `proposed_command` | Must not match any denied-command pattern (see below) |
| `target_paths` | All paths must pass the same path-safety predicate as Layer 1; empty list → `DENY` |

**Denied command categories (representative patterns):**

| Category | Representative patterns |
|---|---|
| Git push / merge / mutate | `git push`, `git merge`, `git rebase`, `git reset`, `git clean`, `git rm` |
| Deploy / release | `deploy`, `release`, `rollout`, `kubectl apply`, `helm upgrade` |
| Infrastructure mutation | `ansible-playbook`, `terraform apply`, `terraform destroy` |
| Registry publish | `npm publish`, `yarn publish`, `twine upload`, `docker push`, `docker build` |
| Network / remote access | `curl`, `wget`, `ssh`, `scp`, `sftp`, `rsync`, `nc`, `socat` |
| Privilege escalation | `sudo`, `su `, `doas`, `pkexec`, `runas` |
| File permission mutation | `chmod`, `chown`, `chgrp`, `setfacl` |
| Destructive file operations | `rm -rf`, `rm -f`, `shred`, `wipe`, `dd if=` |
| Secret / credential access | `aws secretsmanager`, `aws sts`, `az keyvault`, `gcloud secrets`, `vault read/write` |
| Env-var exfiltration | `env >`, `printenv >`, `set >` |
| Production-env targeting | `--env prod`, `--environment production`, `-e prod` |

**Structural invariants on every preflight receipt:**

```
command_executed           = False   ← structural; not a side-effect of denial
command_permitted          = False   ← structural; PREFLIGHT_ADVISORY_ACCEPTED ≠ permitted
real_authority_granted     = False
git_push_performed         = False
deployment_performed       = False
network_call_performed     = False
credential_access_performed= False
human_approval_required    = True    ← structural; cannot be overridden
```

> **Important distinction:**  
> `PREFLIGHT_ADVISORY_ACCEPTED` means the *proposal* passes governance checks.  
> It does **not** mean the command is permitted or will be executed.  
> `command_permitted` remains `False` even when the decision is
> `PREFLIGHT_ADVISORY_ACCEPTED`.

---

### Layer 3 — Replay verifier (`governed_coding_agent_preflight_replay`)

**Pre-checks on the stored receipt:**

| Check | What it catches |
|---|---|
| `stored_receipt_present` | Missing, non-dict, or missing/empty `receipt_hash` |
| `stored_command_executed_false` | Stored receipt claims `command_executed=True` |
| `stored_command_permitted_false` | Stored receipt claims `command_permitted=True` |
| `stored_real_authority_granted_false` | Stored receipt claims `real_authority_granted=True` |

**Field comparison (stored vs. recomputed):**

Every material field is compared.  A single mismatch → `DENY`.

| Field compared | Reason code on mismatch |
|---|---|
| `decision` | `DECISION_MISMATCH` |
| `reason_codes` | `REASON_CODES_MISMATCH` |
| `command_type` | `COMMAND_TYPE_MISMATCH` |
| `target_paths` | `TARGET_PATHS_MISMATCH` |
| `parent_intent_receipt_hash` | `PARENT_INTENT_RECEIPT_HASH_MISMATCH` |
| `command_executed` | `COMMAND_EXECUTED_FLAG_MISMATCH` |
| `command_permitted` | `COMMAND_PERMITTED_FLAG_MISMATCH` |
| `real_authority_granted` | `REAL_AUTHORITY_GRANTED_FLAG_MISMATCH` |
| `human_approval_required` | `HUMAN_APPROVAL_REQUIRED_FLAG_MISMATCH` |
| `receipt_hash` (terminal) | `RECEIPT_HASH_MISMATCH` |
| `prev_preflight_receipt_hash` | `PREV_PREFLIGHT_RECEIPT_HASH_MISMATCH` |

**Hash tamper semantics:**

The `receipt_hash` in a stored receipt is the SHA-256 of all its other fields.
If an attacker modifies any field *without* updating `receipt_hash`, only the
individual field-mismatch reason code fires.  If the attacker *also* corrupts
`receipt_hash`, `RECEIPT_HASH_MISMATCH` fires in addition.  Both cases result
in `DENY`.

**Structural invariants on every replay receipt:**

```
command_executed           = False
command_permitted          = False
real_authority_granted     = False
execution_performed        = False
git_push_performed         = False
deployment_performed       = False
network_call_performed     = False
credential_access_performed= False
```

The verifier does not inherit the tamper it detects.

---

## What is never done at any layer

The following actions are **never performed** by any module in this chain.
This is guaranteed by the absence of any code that does these things, not
merely by a flag:

| Action | Status |
|---|---|
| Execute a shell command | ✗ Never |
| Write to the file system | ✗ Never |
| Make a network request | ✗ Never |
| Read environment variables for secrets | ✗ Never |
| Read credential files | ✗ Never |
| Push to a Git remote | ✗ Never |
| Deploy or restart a service | ✗ Never |
| Modify a database or external state | ✗ Never |
| Escalate privileges | ✗ Never |
| Grant execution authority to itself or an agent | ✗ Never |
| Activate bounded authority | ✗ Never |

---

## Decision tokens are not permissions

| Token | Meaning | Grants execution? |
|---|---|---|
| `INTENT_ADVISORY_ACCEPTED` | Intent is well-formed and advisory | **No** |
| `PREFLIGHT_ADVISORY_ACCEPTED` | Proposal passes preflight governance | **No** |
| `REPLAY_VERIFIED` | Stored receipt matches recomputed receipt | **No** |
| `DENY` | One or more checks failed | **No** |

All four tokens are advisory governance evidence.  None of them activate,
permit, or cause the execution of any action.

---

## Strict-boolean enforcement

All boolean fields in this chain use Python's `is True` / `is False` identity
check rather than truthiness.  This means:

| Value | Passes `advisory_only` check? |
|---|---|
| `True` | ✓ Yes |
| `False` | ✗ No — `ADVISORY_ONLY_REQUIRED` |
| `"true"` | ✗ No — `ADVISORY_ONLY_REQUIRED` |
| `1` | ✗ No — `ADVISORY_ONLY_REQUIRED` |
| `None` | ✗ No — `ADVISORY_ONLY_REQUIRED` |

The same strict check applies to `human_review_required` and
`requires_human_approval`.

---

## Test coverage summary

The safety boundaries above are enforced by a deterministic test suite.

| Module | Test file | Tests |
|---|---|---|
| Intent adapter | `tests/test_governed_coding_agent_intent.py` | 74 |
| Preflight wrapper | `tests/test_governed_coding_agent_preflight.py` | 94 |
| Replay verifier | `tests/test_governed_coding_agent_preflight_replay.py` | 49 |
| End-to-end demo | `tests/test_governed_coding_agent_demo.py` | 46 |
| **Total** | | **263** |

Every test in this suite passes with `execution_performed=False` and
`real_authority_granted=False` as structural invariants.
