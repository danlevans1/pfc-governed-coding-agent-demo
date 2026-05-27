# Architecture — PFC Governed Coding Agent Demo

## Overview

This repository demonstrates a **governance layer that sits at the execution
boundary** between an external AI coding agent and the actions that agent
proposes.  The core claim is simple: governance evidence (receipts) can be
produced, hashed, chained, and replay-verified without the governance layer
itself ever performing the action being evaluated.

The layered design — intent adapter → preflight wrapper → replay verifier —
shows how three independently verifiable checks can be composed into a
bounded proof chain, where each layer can fail closed without affecting the
others and where the entire chain can be recomputed from raw inputs by any
auditor.

---

## The Execution Boundary Concept

External AI coding agents (Claude, Codex, or any advisory agent) can propose
actions.  They cannot cause consequences by themselves.  Between proposal and
consequence sits an execution boundary: the point at which a real action
would be taken (writing a file, pushing a commit, running a process, calling
a network endpoint).

This repository models governance **at that boundary**.  The governance stack
receives a proposal, evaluates it against a rule set, and returns a receipt.
The receipt is evidence about the proposal — it is not permission to act.
No code in this repository ever crosses the execution boundary.

```
External coding agent
  │
  │  "I propose to do X"   (advisory intent)
  ▼
┌─────────────────────────────────────────────────────────┐
│                  Governance Stack                        │
│                                                         │
│  Layer 1: Intent Adapter      (validates the proposal)  │
│  Layer 2: Preflight Wrapper   (validates the command)   │
│  Layer 3: Replay Verifier     (validates the receipt)   │
└─────────────────────────────────────────────────────────┘
  │
  │  receipt (evidence, not permission)
  ▼
Human review gate
  │
  │  (human decides whether to act)
  ▼
Execution boundary        ← this repository never reaches this point
```

---

## System Components

### `src/governance_decision.py`

Defines the three decision tokens used throughout the stack:

- `ALLOW` — action is within policy
- `DENY` — action is outside policy
- `REQUIRE_HUMAN_APPROVAL` — action requires explicit operator sign-off

These are plain strings, not permission grants.  A receipt carrying `ALLOW`
does not cause anything to execute; it is evidence that the proposal passed
the governance check at the time of evaluation.

`build_decision`, `allow`, `deny`, and `require_human_approval` are
thin constructors that attach a `gate_name`, `reason` string, and `checks`
dict to the decision token.

### `src/governance_hashing.py`

Two primitives:

- `canonical_json(data)` — serialises a dict with `sort_keys=True` and no
  unnecessary whitespace, producing a stable byte sequence regardless of
  Python's dict insertion order.
- `deterministic_hash(data)` — SHA-256 of the canonical JSON encoding.

The hash is computed after every other receipt field is finalised so that it
commits to the complete receipt payload.  Altering any field — including any
structural invariant flag — invalidates the hash and is detectable by the
replay verifier.

---

## Layer 1 — Intent Adapter

**File:** `src/governed_coding_agent_intent.py`  
**Entry point:** `evaluate_coding_agent_intent(intent)`  
**Public decision token:** `INTENT_ADVISORY_ACCEPTED`

### Purpose

Normalise and validate advisory intent submitted by an external coding agent.
The intent is a plain dict describing a proposed action.  The adapter checks
that the intent is coherent, bounded, and advisory-only before producing a
hashed receipt.

### Validation rules

| Check | Predicate |
|---|---|
| `intent_id_present` | non-empty string |
| `agent_id_present` | non-empty string |
| `agent_type_present` | non-empty string |
| `advisory_only_set` | must be strictly `True` |
| `human_review_required_set` | must be strictly `True` |
| `action_allowed` | must be in `ALLOWED_ACTIONS` vocabulary |
| `risk_within_bound` | must be `"low"` or `"bounded"` |
| `path_safe` | repo-relative, no forbidden path patterns |

All eight checks must pass for the decision to be `INTENT_ADVISORY_ACCEPTED`.
Any failure yields `DENY` with a sorted list of `reason_codes`.

### Bounded vocabulary (`ALLOWED_ACTIONS`)

Only three actions are in scope:
```
propose_file_change
propose_test_run
propose_commit
```

Any other value fails `action_allowed`.  This prevents the intent adapter
from reasoning about actions it was not designed to evaluate.

### Path safety (`_FORBIDDEN_PATH_PATTERNS`)

Paths are checked against a compiled regex deny-list that rejects:

- Path traversal (`../`, `..\`)
- `.env` files and variants
- `secrets/`, `credentials/` directories
- `deploy/`, `deployment/` directories
- `prod/`, `production/` directories
- Private key extensions (`.key`, `.pem`, `.crt`, `.p12`, `.pfx`)
- Well-known SSH key filenames
- Infra config directories (`terraform/`, `ansible/`, `k8s/`, `kubernetes/`)
- CI/CD pipeline definitions (`.github/`, `.gitlab/`, `.circleci/`)

Absolute paths (starting with `/` or `C:\`) are always rejected because the
intent schema only makes sense for repo-relative paths.

### Structural invariant flags (`INTENT_FLAGS`)

Every intent receipt carries these fields locked to `False`, regardless of
decision outcome:

```
execution_performed        = False
execution_permitted        = False
real_authority_granted     = False
git_push_performed         = False
deployment_performed       = False
network_call_performed     = False
credential_access_performed= False
advisory_only              = True   (always True, not False)
```

These fields are included in the receipt hash.  Flipping any of them breaks
the hash commitment.

### Receipt hashing

`generate_intent_receipt` constructs the full receipt dict — including all
invariant flags — and appends `receipt_hash = deterministic_hash(receipt)`
as the final step.  The hash therefore covers every material field.

Receipts also carry `issued_at`, `expires_at`, and `ttl_seconds` (fixed demo
constants; see [Freshness](#receipt-freshness-and-expiry) below).

---

## Layer 2 — Preflight Wrapper

**File:** `src/governed_coding_agent_preflight.py`  
**Entry point:** `evaluate_coding_agent_preflight(...)`  
**Public decision token:** `PREFLIGHT_ADVISORY_ACCEPTED`

### Purpose

Before a proposed command is sent to human review, validate it against a
second, independent rule set.  The preflight wrapper receives the original
intent, the intent receipt from Layer 1, and the proposed command string.
It re-validates the intent inline (defence in depth), checks the proposed
command against a deny-list, and verifies the parent receipt hash.

### Defence in depth

The preflight wrapper calls `validate_coding_agent_intent` independently,
even though Layer 1 already ran.  This means a tampered intent cannot pass
Layer 2 simply because it once passed Layer 1: the rules are re-evaluated
from the raw intent dict on every preflight call.

### Parent receipt linkage

The caller supplies both the parent intent receipt dict and the
`parent_intent_receipt_hash` they recorded.  The preflight wrapper checks:

1. The parent receipt carries `decision == INTENT_ADVISORY_ACCEPTED`.
2. The parent receipt carries `advisory_only = True`.
3. The parent receipt carries `execution_performed = False`.
4. The parent receipt carries `real_authority_granted = False`.
5. The provided `parent_intent_receipt_hash` matches `receipt["receipt_hash"]`
   inside the parent receipt.

Check 5 binds the preflight evaluation to a specific, unmodified instance of
the intent receipt.  A different intent receipt, or a modified copy of the
same receipt, will fail the hash comparison.

### Command deny-list (`_DENIED_COMMAND_PATTERNS`)

The proposed command string is checked against compiled regex patterns that
reject:

- Git mutations: `push`, `merge`, `rebase`, `reset`, `clean`, `rm`, `mv`, etc.
- Deploy/release tooling: `deploy`, `release`, `publish`, `kubectl apply`,
  `helm upgrade`, `ansible-playbook`, `terraform apply/destroy`
- Package registry pushes: `npm publish`, `pip upload`, `twine upload`,
  `docker push/tag/build`
- Network access: `curl`, `wget`, `ssh`, `scp`, `sftp`, `rsync`, `nc`
- Privilege escalation: `sudo`, `su`, `doas`, `pkexec`, `runas`
- File-permission mutation: `chmod`, `chown`, `chgrp`, `setfacl`
- Destructive file operations: `rm -rf`, `shred`, `wipe`, `dd if=`
- Secret/credential access tools: `aws sts`, `az keyvault`, `vault read`, etc.
- Environment exfiltration: `env >`, `printenv >`, `set >`
- Production-targeting keywords: `--env prod`, `--environment prod`

Any match yields `DENY` with `COMMAND_DENIED`.

### Allowed command types (`ALLOWED_COMMAND_TYPES`)

The `command_type` field must be one of:

```
inspect_diff
run_focused_tests
propose_commit
```

This is independent of the deny-list check: a command that passes the
pattern check but uses an unlisted `command_type` still fails.

### Structural invariant flags (`PREFLIGHT_FLAGS`)

Every preflight receipt carries these fields locked:

```
command_executed           = False
command_permitted          = False
real_authority_granted     = False
human_approval_required    = True
git_push_performed         = False
deployment_performed       = False
network_call_performed     = False
credential_access_performed= False
```

---

## Layer 3 — Replay Verifier

**File:** `src/governed_coding_agent_preflight_replay.py`  
**Entry point:** `verify_preflight_replay(...)`  
**Public decision token:** `REPLAY_VERIFIED`

### Purpose

Given a stored preflight receipt and the original raw inputs that produced it,
independently recompute the receipt and compare every material field.  If any
field differs, the stored receipt is rejected.

This is the key architectural distinction from a conventional audit log: the
verifier does not trust the stored receipt; it proves the stored receipt
against a fresh computation.

### Verification flow

```
Phase 1 — Pre-replay checks (on the stored receipt)
  stored_receipt_present            : receipt is a non-empty dict with receipt_hash
  stored_command_executed_false     : stored["command_executed"] is False
  stored_command_permitted_false    : stored["command_permitted"] is False
  stored_real_authority_granted_false: stored["real_authority_granted"] is False
  receipt_not_expired               : stored["expires_at"] > check_at

Phase 2 — Replay
  Re-run evaluate_coding_agent_preflight from the original raw inputs
  to produce a recomputed receipt.

Phase 3 — Field-by-field comparison (stored vs recomputed)
  decision, reason_codes, command_type, target_paths,
  parent_intent_receipt_hash, command_executed, command_permitted,
  real_authority_granted, human_approval_required, receipt_hash

Phase 4 — Prev-hash consistency
  prev_preflight_receipt_hash matches between stored and recomputed.

Decision: REPLAY_VERIFIED only if every check passes.
```

Phase 1 rejects stored receipts that falsely claim execution or authority,
regardless of whether the hash would match.  Phase 3 rejects receipts where
any field was changed after issuance.  Phase 5 catches any field not covered
by Phase 3 by failing the terminal `receipt_hash` comparison.

### Semantic tamper detection

A standard log integrity check (append-only log, Merkle tree) detects
insertion or deletion of log entries.  It does not detect a receipt whose
fields were all consistent at write time but whose claims are false — for
example, a receipt that was issued with `real_authority_granted=True` set by a
compromised issuer.

The replay verifier addresses a stronger property: it checks that the stored
receipt's claims are *consistent with what the governance rules would have
decided* given the original raw inputs.  A receipt that was issued with
fabricated field values will fail Phase 3 when the recomputed values differ.

### Receipt lineage

The `prev_receipt_hash` fields in intent receipts, and
`prev_preflight_receipt_hash` in preflight receipts, allow sequential receipts
to be chained.  Each receipt commits to the hash of its predecessor.
The replay verifier checks that the `prev_preflight_receipt_hash` field is
consistent between the stored and recomputed receipt.

### Receipt freshness and expiry

Every receipt carries three freshness fields (fixed demo constants):

```
issued_at   : "2026-05-26T00:00:00Z"   (when the receipt was issued)
ttl_seconds : 3600                      (how long the receipt is valid)
expires_at  : "2026-05-26T01:00:00Z"   (issued_at + ttl_seconds)
```

`verify_preflight_replay` accepts a `check_at` keyword argument (an ISO-8601
UTC string).  If `expires_at ≤ check_at`, the check `receipt_not_expired` is
`False` and the decision is `DENY` with reason code `RECEIPT_EXPIRED`.

The default value of `check_at` is `DEMO_CHECK_AT = "2026-05-26T00:30:00Z"`,
a fixed constant within the demo TTL window, so that the default demonstration
path always produces `REPLAY_VERIFIED` deterministically.  Tests that exercise
the expiry path pass an explicit `check_at` value after `DEMO_EXPIRES_AT`.

In a production system, `check_at` would be replaced by a trusted monotonic
clock source with verifiable provenance.

---

## Design Principles

### Fail-closed semantics

Every validation function returns `DENY` on any missing, unexpected, or
malformed input.  There is no "default allow" path.  A receipt is issued
regardless of outcome, but the decision field is always `DENY` unless every
check explicitly passes.

### Receipts are evidence, not trust

A receipt carrying `INTENT_ADVISORY_ACCEPTED` is a record that the governance
stack evaluated the intent and found it within policy.  It is not a token that
grants permission, activates execution, or establishes trust between the
governance stack and the execution boundary.

The execution boundary is an external concern.  This repository models the
governance layer only.  Treating a receipt as a permission token would
require an additional trust relationship that this codebase does not establish.

### Deterministic replayability

Given the same raw inputs, every layer produces the same outputs on every
invocation.  There are no random nonces, no wall-clock timestamps, no
environment dependencies.  This property means the full governance chain can
be recomputed by any party with access to the inputs and the source code,
without requiring access to the original evaluation environment.

The freshness timestamps are fixed demo constants for the same reason:
determinism is more valuable for a reference architecture than
approximate time accuracy.

### Structural invariants

No-execution flags (`execution_performed`, `command_executed`,
`real_authority_granted`, etc.) are defined as module-level constants
(`INTENT_FLAGS`, `PREFLIGHT_FLAGS`, `REPLAY_FLAGS`) and spread into every
receipt unconditionally.  They are not conditionally included or excluded
based on the decision outcome.  Any code path that omits them would produce
a receipt with a different hash, detectable by replay.

### No temporal authority carry

A receipt is valid only within its TTL window.  Replay verification
rejects receipts whose `expires_at` is in the past relative to `check_at`.
A governance decision made at time T cannot carry authority forward to
time T+n simply because it was once accepted.  Each evaluation is bounded.

### Governance separated from execution

The governance stack and the execution boundary are intentionally modelled as
separate concerns.  The governance stack outputs receipts.  A separate
execution boundary (not modelled here) would receive receipts, verify them,
and decide whether to proceed.  This separation means the governance stack
can be audited, tested, and reasoned about independently of any particular
execution runtime.

### Advisory-only boundaries

Every receipt asserts `advisory_only = True` (intent receipts) and
`human_approval_required = True` (preflight receipts).  These are structural,
not advisory.  No receipt can cause an action by itself.

---

## Intentional Omissions

This repository explicitly does not include:

| Omission | Reason |
|---|---|
| Subprocess / shell execution | Out of scope; the governance stack never reaches the execution boundary |
| File system mutation | Same — evaluation is read-only with respect to the file system |
| Git push or any Git mutation | Explicitly blocked in both the deny-list and the intent |
| Deployment logic | Explicitly blocked; `deploy*` patterns in both deny-list and path rules |
| Network access | No socket, HTTP, or DNS call anywhere in the stack |
| Credential access | No secrets manager, keyring, or `.env` file reader |
| Real execution authority | The structural invariant flags make this impossible by construction |
| OS-level sandboxing | Out of scope; see [Deny-list Limitations](#deny-list-limitations) |
| Cryptographic signing | Out of scope for a demo; see [Productionization](#productionization) |
| Trusted hardware clock | Out of scope; see [Productionization](#productionization) |

---

## Why Replay Verification Matters

### The problem with post-hoc logs

A conventional audit log records what the system decided.  If the log is
append-only and tamper-evident (hash-chained, Merkle-rooted, signed), you can
detect whether a log entry was added, removed, or reordered after the fact.

But you cannot detect a log entry that was written correctly at the time
it was recorded, by a compromised or incorrectly-configured issuer, claiming
a decision it should not have made.

### What replay verification adds

The replay verifier recomputes the governance decision from the original raw
inputs and compares the result against what the stored receipt claims.  A
receipt whose claims differ from what a fresh computation produces is rejected,
regardless of whether its hash is internally consistent.

This means:
1. A receipt issued by a compromised Layer 2 with `command_permitted=True` is
   caught in Phase 1 of verification (pre-replay structural checks).
2. A receipt whose `decision` was changed from `DENY` to
   `PREFLIGHT_ADVISORY_ACCEPTED` is caught in Phase 3 (field comparison).
3. A receipt whose `receipt_hash` was regenerated after tampering to make it
   internally consistent is still caught, because the recomputed receipt
   (derived from honest raw inputs) produces a different hash.

### Independently reproducible decisions

Because the governance rules are pure functions of their inputs (no
side-effects, no external state), any party with the raw inputs and the source
code can reproduce the governance decision and verify any stored receipt.  This
is a stronger property than a signed log: a signed log proves *who signed*;
deterministic replay proves *what would have been decided*.

---

## Deny-list Limitations

The command deny-list in Layer 2 (`_DENIED_COMMAND_PATTERNS`) is a pattern
match over the *string representation* of the proposed command.  It is
illustrative, not exhaustive.  Its limitations include:

- **String-level only.** The patterns match command strings as written.
  Unicode homoglyphs, shell quoting, environment variable expansion,
  or creative whitespace can produce strings that bypass pattern matching
  without the underlying command changing meaning.

- **No parse tree.** The deny-list does not parse command syntax.  A `rm`
  with unusual flag ordering, or a pipeline whose second stage is dangerous,
  may not match the patterns as written.

- **No execution context.** The deny-list does not know whether the command
  would run in a container, a CI job, or a production host.  The same string
  may be dangerous in one context and benign in another.

- **Intentionally advisory.** The deny-list exists to demonstrate the
  *pattern* of command-string governance, not to provide a complete security
  control.

In a production deployment, string-matching over proposed command strings
would be supplemented or replaced by:

- Process-level isolation (containers, VMs, `seccomp` filter profiles)
- Linux capabilities or capability-scoped execution
- Mandatory access control (AppArmor, SELinux policy)
- Hardware-enforced memory protection

These controls operate below the Python layer and cannot be bypassed by
constructing unusual command strings.

---

## Productionization

A production-grade implementation of this governance pattern would additionally
require:

### Trusted clocks

The demo uses fixed string constants for `issued_at` and `expires_at`.
A production system requires a clock source whose output is verifiable and
monotonic — for example, a network time protocol with cryptographic
authentication (RFC 8915), or a hardware security module that signs
timestamps.

### Signed verifier keys

The demo receipt hash is a SHA-256 commitment.  It proves internal
consistency but does not prove *who computed it*.  A production receipt should
be signed by a key whose provenance can be verified — an asymmetric keypair
stored in an HSM or a cloud KMS, with a published verifier key.

### Transparency logs

For governance decisions that have regulatory or audit significance, receipts
should be submitted to a transparency log (similar to Certificate Transparency)
where inclusion proofs can be independently verified by third parties.

### Capability-scoped execution

The demo separates governance from execution conceptually.  A production
system would enforce this separation with OS-level capability controls: the
process that evaluates governance evidence would have no capabilities to
write files, open network connections, or fork subprocesses.

### Hardened sandbox runtime

Proposed commands that pass governance review and are approved for execution
should run inside a hardened sandbox runtime — a minimal container image with
`seccomp` profiles, no network access, and read-only filesystem mounts
except for the specific output path.

### Process isolation

The governance evaluation process and the command execution process should be
separate OS processes with no shared memory.  A compromised execution process
cannot affect governance logic.

### Policy distribution and versioning

The governance rules (allowed actions, deny-list patterns, path predicates)
are embedded in source code in this demo.  A production system requires a
policy distribution mechanism: versioned policy packages, cryptographic
policy integrity, and a clear audit trail of which policy version evaluated
which receipt.

### Replay windows

The demo TTL is a fixed constant.  A production system requires configurable
replay windows by receipt type, with explicit revocation for receipts that
should be rejected before their TTL expires.

### Revocation semantics

A receipt that was issued correctly but whose underlying conditions have
changed (the file has been modified, the agent's credentials have been
revoked) should be revocable.  This requires a revocation registry that is
checked during replay verification.

### Operator approval workflows

`REQUIRE_HUMAN_APPROVAL` is defined as a decision token but is not connected
to a workflow in this demo.  A production system requires an operator approval
interface that is tightly coupled to the receipt: the operator approves a
specific receipt hash, not a general class of action.

---

## Data Flow Summary

```
Raw inputs (intent dict)
  │
  ▼
validate_coding_agent_intent()
  │  checks: 8 boolean predicates
  │  output: {decision, checks, reason_codes, advisory_only}
  │
  ▼
generate_intent_receipt()
  │  adds: identity fields, freshness fields, invariant flags
  │  appends: receipt_hash = SHA-256(canonical_json(receipt))
  │  output: immutable intent receipt
  │
  ▼
validate_coding_agent_preflight()
  │  re-validates intent (defence in depth)
  │  checks: 7 boolean predicates
  │  output: {decision, checks, reason_codes, command_executed=False, …}
  │
  ▼
generate_preflight_receipt()
  │  adds: parent linkage, freshness fields, invariant flags
  │  appends: receipt_hash = SHA-256(canonical_json(receipt))
  │  output: immutable preflight receipt
  │
  ▼
verify_preflight_replay()
  │  phase 1: 5 pre-replay structural checks (including expiry)
  │  phase 2: recompute receipt from raw inputs
  │  phase 3: 10 field-by-field comparisons
  │  phase 4: prev_hash consistency
  │  appends: receipt_hash = SHA-256(canonical_json(replay_receipt))
  │  output: REPLAY_VERIFIED or DENY with reason_codes
  │
  ▼
Human review gate
```
