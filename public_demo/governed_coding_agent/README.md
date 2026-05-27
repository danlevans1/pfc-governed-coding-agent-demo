# Governed Coding Agent — Public Proof Package

> **Advisory / simulation-only.** Nothing in this package executes commands,
> mutates files, pushes to Git, deploys, calls the network, accesses
> credentials, or grants execution authority.  PFC is the execution boundary.

---

## What this is

This package demonstrates a **governed coding-agent proof chain** for the
PFC Local Agent project.  It shows how an external coding agent (Claude, Codex,
or any advisory agent) can propose intent that PFC evaluates, preflights, and
replay-verifies — all without granting real-world authority.

The goal is to prove the governance structure works correctly before any
execution authority is ever considered.

---

## The bounded proof chain

```
External coding agent
  │
  │  submit intent
  ▼
[ PFC Intent Adapter ]
  │  • validates advisory_only=True
  │  • validates human_review_required=True
  │  • validates requested_action ∈ allowed advisory verbs
  │  • validates risk_level ≤ bounded
  │  • validates target_path is repo-relative, no secrets/deploy/prod paths
  │  emits → intent receipt  (SHA-256 hash-linked)
  │
  │  INTENT_ADVISORY_ACCEPTED  ──or──  DENY + reason_codes
  ▼
[ PFC Preflight Wrapper ]
  │  • parent intent receipt must be INTENT_ADVISORY_ACCEPTED
  │  • parent receipt hash must match (tamper detection)
  │  • intent re-validated inline (defence in depth)
  │  • proposed_command checked against deny-list
  │  • command_type must be simulated-only
  │  • all target_paths must be repo-relative and safe
  │  emits → preflight receipt  (SHA-256 hash-linked)
  │
  │  PREFLIGHT_ADVISORY_ACCEPTED  ──or──  DENY + reason_codes
  ▼
[ PFC Replay Verifier ]
  │  • independently recomputes receipt from raw inputs
  │  • compares every material field to the stored receipt
  │  • catches tampered decision, reason_codes, flags, or hash
  │  emits → replay receipt  (SHA-256 hash-linked)
  │
  │  REPLAY_VERIFIED  ──or──  DENY + reason_codes
  ▼
Human review  (no execution yet)
```

---

## Files in this package

| File | Contents |
|---|---|
| `README.md` | This file — overview and navigation |
| `demo_flow.md` | Step-by-step annotated walkthrough of all three demo scenarios |
| `sample_receipts.md` | Actual JSON receipts produced by the live demo |
| `safety_boundaries.md` | Detailed safety guarantee reference |

---

## Running the demo

From the repository root:

```bash
PYTHONPATH=. .venv/bin/python -m examples.governed_coding_agent_demo
```

All three scenarios print to stdout.  Exit code is `0` when every scenario
produces the expected decision, `1` otherwise.

---

## Key invariants

These flags appear on **every** receipt — intent, preflight, and replay —
regardless of the governance decision:

| Flag | Value |
|---|---|
| `command_executed` | `False` |
| `command_permitted` | `False` |
| `real_authority_granted` | `False` |
| `execution_performed` | `False` |
| `git_push_performed` | `False` |
| `deployment_performed` | `False` |
| `network_call_performed` | `False` |
| `credential_access_performed` | `False` |
| `human_approval_required` | `True` (preflight) |
| `advisory_only` | `True` (intent) |

---

## What this is not

- This is **not** a live execution system.
- Receipts are **not** approvals to run commands.
- `PREFLIGHT_ADVISORY_ACCEPTED` does **not** mean a command will be run.
- `REPLAY_VERIFIED` does **not** grant any authority.

All decisions are advisory evidence for future human review only.
