# PFC Governed Coding Agent Demo

> **Advisory / simulation-only.**  This repository never executes shell
> commands, pushes to Git, deploys, calls the network, accesses credentials,
> or grants execution authority.  PFC is the execution boundary.

---

## What this is

A standalone, public-safe demonstration of the **PFC governed coding-agent
proof chain** — a minimal governance stack that shows how external coding
agents (Claude, Codex, or any advisory agent) can propose intent that PFC
evaluates, preflights, and replay-verifies, all without granting real-world
execution authority.

The full layered stack lives in the private PFC Local Agent repository.  This
repo contains only the public-safe subset needed to run the demo end-to-end.

---

## The bounded proof chain

```
External coding agent (Claude / Codex)
  │
  │  submit advisory intent
  ▼
[ PFC Intent Adapter ]         src/governed_coding_agent_intent.py
  │  validates advisory_only, human_review_required, allowed actions,
  │  risk ≤ bounded, repo-relative safe path
  │  → INTENT_ADVISORY_ACCEPTED  or  DENY + reason_codes
  │
  ▼
[ PFC Preflight Wrapper ]      src/governed_coding_agent_preflight.py
  │  validates parent receipt hash, re-validates intent,
  │  command deny-list, allowed command types, safe paths
  │  → PREFLIGHT_ADVISORY_ACCEPTED  or  DENY + reason_codes
  │
  ▼
[ PFC Replay Verifier ]        src/governed_coding_agent_preflight_replay.py
  │  independently recomputes receipt, compares every material field
  │  → REPLAY_VERIFIED  or  DENY + reason_codes
  │
  ▼
Human review  (no execution authority granted at any step)
```

---

## Quick start

```bash
# 1. Clone and enter
git clone <this-repo>
cd pfc-governed-coding-agent-demo

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the demo
PYTHONPATH=. python -m examples.governed_coding_agent_demo

# 5. Run the tests
PYTHONPATH=. pytest tests/test_governed_coding_agent_demo.py -q
```

---

## Repository layout

```
pfc-governed-coding-agent-demo/
├── src/
│   ├── __init__.py
│   ├── governance_decision.py              # DENY / ALLOW / REQUIRE_HUMAN_APPROVAL tokens
│   ├── governance_hashing.py               # deterministic SHA-256 receipt hashing
│   ├── governed_coding_agent_intent.py     # Layer 1 — intent adapter
│   ├── governed_coding_agent_preflight.py  # Layer 2 — preflight wrapper
│   └── governed_coding_agent_preflight_replay.py  # Layer 3 — replay verifier
├── examples/
│   └── governed_coding_agent_demo.py       # end-to-end demo script (3 scenarios)
├── tests/
│   └── test_governed_coding_agent_demo.py  # 46 tests (all pass)
├── public_demo/
│   └── governed_coding_agent/
│       ├── README.md                       # chain overview + ASCII flow diagram
│       ├── demo_flow.md                    # annotated scenario walkthroughs
│       ├── sample_receipts.md              # live JSON receipt output
│       └── safety_boundaries.md            # comprehensive safety reference
├── LICENSE                                 # MIT
├── requirements.txt                        # pytest only
└── README.md                              # this file
```

---

## Demo scenarios

### Scenario A — Accepted advisory flow

Claude proposes a test run.  All three governance layers accept:

```
INTENT_ADVISORY_ACCEPTED  →  PREFLIGHT_ADVISORY_ACCEPTED  →  REPLAY_VERIFIED
```

Every receipt carries `command_executed=False`, `command_permitted=False`,
`real_authority_granted=False`.

### Scenario B — Dangerous command denied

Codex proposes `git push origin main`.  The preflight deny-list fires:

```
INTENT_ADVISORY_ACCEPTED  →  DENY  (reason: COMMAND_DENIED)
```

Even on denial, all no-execution flags remain `False`.

### Scenario C — Tampered receipt caught

A valid preflight receipt is tampered (`real_authority_granted=True`,
`command_permitted=True`, hash corrupted).  The replay verifier catches all
three violations:

```
REPLAY: DENY
reason_codes: [COMMAND_PERMITTED_FLAG_MISMATCH,
               REAL_AUTHORITY_GRANTED_FLAG_MISMATCH,
               RECEIPT_HASH_MISMATCH,
               STORED_RECEIPT_CLAIMS_COMMAND_PERMITTED,
               STORED_RECEIPT_CLAIMS_REAL_AUTHORITY_GRANTED]
```

The replay receipt itself still carries `real_authority_granted=False`.

---

## Key safety invariants

These flags appear on **every** receipt — regardless of decision outcome:

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

Decision tokens (`INTENT_ADVISORY_ACCEPTED`, `PREFLIGHT_ADVISORY_ACCEPTED`,
`REPLAY_VERIFIED`) are **advisory governance evidence only**.  None of them
activate, permit, or cause the execution of any action.

---

## Further reading

See [`public_demo/governed_coding_agent/`](public_demo/governed_coding_agent/)
for the annotated walkthrough, live sample receipts, and the full safety
boundary reference.
