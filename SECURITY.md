# Security Notes — PFC Governed Coding Agent Demo

> **This repository is advisory / simulation-only.**
> It is a public demonstration of a governance proof-chain, not a production
> security control.  The limits described here are enforced by code design and
> structural invariants, not by an OS-level sandbox.

---

## What this demo never does

| Capability | Status | Detail |
|---|---|---|
| Shell execution | **Never** | No `subprocess`, `os.system`, `exec`, or equivalent call exists in the codebase. |
| Git push | **Never** | No `git push` or Git-mutation operation is issued. `COMMAND_DENIED` fires on any `git push` in a proposed command string. |
| Deployment | **Never** | No deploy, release, rollout, or cloud-infra command is issued or simulated. |
| Network calls | **Never** | No `socket`, `http`, `requests`, `urllib`, `curl`, or equivalent call exists. |
| Credential access | **Never** | No secrets manager, keyring, `.env` file, or cloud credential API is touched. |
| Execution authority | **Never** | `execution_performed`, `command_executed`, `command_permitted`, and `real_authority_granted` are structural `False` invariants on every receipt. |

---

## Structural invariant flags

Every receipt emitted by this demo — regardless of whether the governance
decision is `ALLOW`, `DENY`, or `REQUIRE_HUMAN_APPROVAL` — carries all of the
following flags locked to their invariant values:

```
execution_performed        = False
execution_permitted        = False
real_authority_granted     = False
command_executed           = False
command_permitted          = False
git_push_performed         = False
deployment_performed       = False
network_call_performed     = False
credential_access_performed= False
advisory_only              = True   (intent receipts)
human_approval_required    = True   (preflight receipts)
```

These flags are included in the SHA-256 `receipt_hash` that covers the full
receipt payload, so any attempt to flip them invalidates the hash and is caught
by the replay verifier.

---

## Known limitation — regex deny-list is a demo guard, not a sandbox

The `governed_coding_agent_preflight` module uses a regex deny-list
(`_DENIED_COMMAND_PATTERNS`) to block dangerous command strings.

**This is a demo-quality guard, not an OS-level sandbox.**

Specifically:
- It operates on advisory *proposed command strings*, not on actually executed
  processes.  No command is ever executed, so there is nothing to sandbox.
- Regex pattern matching on strings is bypassable by creative encoding, Unicode
  tricks, or command composition that the patterns do not anticipate.
- The path-safety predicates (`_FORBIDDEN_PATH_PATTERNS`) similarly operate on
  string matching, not on filesystem access controls.

In a production deployment, advisory governance evidence (receipts) should be
combined with OS-level process isolation, seccomp filters, or equivalent
sandboxing mechanisms.  This demo does not provide those controls.

---

## Receipt freshness

Receipts carry deterministic demo timestamps (`issued_at`, `expires_at`,
`ttl_seconds`).  The replay verifier accepts a `check_at` parameter and returns
`DENY` with reason code `RECEIPT_EXPIRED` when `expires_at ≤ check_at`.

These timestamps are **fixed demo constants**, not real-time clock values.
They exist to demonstrate the freshness-verification pattern; they do not
constitute a real-time access-control mechanism.

---

## Reporting

This is a public demonstration repository.  If you find a logic error or a
missed invariant, please open a GitHub issue.  There is no bug-bounty programme
for this demo.

---

## Scope summary

```
IN SCOPE  (what this demo models)
  ✓  Advisory intent governance
  ✓  Deterministic receipt hashing
  ✓  Preflight command-string deny-listing
  ✓  Replay tamper-detection
  ✓  Receipt freshness / expiry demonstration

OUT OF SCOPE  (not modelled here)
  ✗  Real shell execution or sandboxing
  ✗  Real network access or isolation
  ✗  Real credential management
  ✗  Real Git operations
  ✗  Real deployment pipelines
  ✗  Production-grade access control
```
