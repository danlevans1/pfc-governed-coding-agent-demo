# Threat Model — PFC Governed Coding Agent Demo

## Scope

This threat model covers the governance logic implemented in this repository.
It does not cover the execution boundary, the operator environment, the CI/CD
pipeline that runs this code, or the runtime infrastructure.

The repository models **advisory intent governance** — receiving a proposal
from an external coding agent, evaluating it against governance rules, and
returning a receipt.  It does not execute proposals.  It does not control the
execution boundary.  Claims about what the execution boundary should do in
response to a receipt are out of scope.

---

## Assets

| Asset | Description |
|---|---|
| Governance receipts | The primary output: structured dicts with decision, checks, reason_codes, invariant flags, and a SHA-256 receipt_hash |
| Governance rules | The validation predicates, deny-list patterns, path predicates, and allowed vocabularies embedded in source code |
| Structural invariants | The no-execution flags (`real_authority_granted`, `command_executed`, etc.) that must always be `False` |
| Receipt lineage | The `prev_receipt_hash` chain linking sequential receipts |

---

## Principals

| Principal | Trust level | Description |
|---|---|---|
| External coding agent | Untrusted | Submits intent dicts; assumed to be adversarial |
| Governance stack | Trusted | This codebase; assumed to execute honestly |
| Human reviewer | Out of scope | Receives receipts; acts or not at their discretion |
| Replay verifier | Trusted | Recomputes receipts; must have access to raw inputs and source |

---

## Threats Demonstrated

The three demo scenarios directly exercise the following threat classes.

### Dangerous command escalation (Scenario B)

**Threat:** An external agent submits a valid advisory intent but pairs it with
a proposed command that would cause a harmful real-world consequence
(`git push origin main`, `deploy`, `curl`, etc.).

**Mitigation:** The Layer 2 preflight deny-list (`_DENIED_COMMAND_PATTERNS`)
rejects the proposed command before the receipt is issued with an accepted
decision.  The preflight receipt carries `DENY` with reason code
`COMMAND_DENIED`.  Structural invariant flags remain `False` on the denied
receipt.

**Demonstrated in:** `scenario_b()` → `TestScenarioB`

---

### Semantic tampering (Scenario C)

**Threat:** A receipt is modified after issuance to claim execution authority
that the governance stack never granted.  Specifically: a valid
`PREFLIGHT_ADVISORY_ACCEPTED` receipt is altered so that
`real_authority_granted = True` and `command_permitted = True`.

**Mitigation:**
1. Pre-replay structural checks (Phase 1 of `verify_preflight_replay`) detect
   `command_permitted = True` and `real_authority_granted = True` before the
   replay even runs, yielding `STORED_RECEIPT_CLAIMS_COMMAND_PERMITTED` and
   `STORED_RECEIPT_CLAIMS_REAL_AUTHORITY_GRANTED` reason codes.
2. The terminal `receipt_hash` comparison (Phase 3) detects the mismatch
   between the tampered hash and the hash of the recomputed receipt, yielding
   `RECEIPT_HASH_MISMATCH`.

The replay verifier returns `DENY` regardless of whether the tampered receipt
is internally self-consistent.

**Demonstrated in:** `scenario_c()` → `TestScenarioC`

---

### Forged governance claims

**Threat:** An external agent submits an intent whose fields claim properties
it does not have: `advisory_only = False`, `risk_level = "critical"`, or an
action not in the allowed vocabulary.

**Mitigation:** The Layer 1 intent adapter evaluates each field independently.
Any single failure yields `DENY`.  The validation logic has no "almost correct"
path; a claim must be exactly correct or the check fails.

**Demonstrated in:** individual validation unit tests.

---

### Replay inconsistency

**Threat:** A receipt is stored correctly at issuance, but the raw inputs are
later modified so that replaying the receipt would produce a different decision.
An adversary could then present the old receipt as evidence of a governance
decision that would no longer be reached.

**Mitigation:** The replay verifier recomputes the governance decision from the
raw inputs at verification time.  If the raw inputs have changed (different
intent dict, different proposed command, different parent receipt hash), the
recomputed receipt differs from the stored receipt and Phase 3 fails.

The receipt lineage chain (`prev_receipt_hash`) additionally links each receipt
to its predecessor, making it detectable if a receipt from one chain is
presented as belonging to a different chain.

---

### Path traversal

**Threat:** An agent submits a `target_path` of `../../.ssh/id_rsa` or similar
to attempt to reference files outside the repository root or in sensitive
system locations.

**Mitigation:** `_path_safe()` in the intent adapter rejects any path
containing `../` or `..\`, any absolute path, and any path matching the
forbidden path patterns (secrets, credentials, deploy, prod, private keys,
SSH key filenames, CI/CD pipeline dirs).

---

### Privilege escalation attempts

**Threat:** A proposed command includes `sudo`, `su`, `pkexec`, `runas`, or
similar privilege-escalation primitives.

**Mitigation:** `_DENIED_COMMAND_PATTERNS` in the preflight wrapper rejects
any proposed command matching `\b(sudo|su\s|doas|pkexec|runas)\b`.

---

### Secret-access attempts

**Threat:** A proposed command includes AWS SSM, Azure Key Vault, GCP secrets,
HashiCorp Vault, or OS keyring commands.

**Mitigation:** `_DENIED_COMMAND_PATTERNS` rejects commands matching
`aws\s+(sts|secretsmanager|ssm)`, `az\s+keyvault`, `gcloud\s+secrets`,
`vault\s+(read|write|delete)`, `keyring`, `secret-tool`, and `pass`.

---

### Production-targeted commands

**Threat:** A proposed command includes explicit production-environment
targeting flags (`--env prod`, `--environment prod`, `-e prod`, or the word
`production` in the command string itself).

**Mitigation:** `_DENIED_COMMAND_PATTERNS` rejects commands containing
`\b(production|--env\s+prod|--environment\s+prod|-e\s+prod)\b`.

---

### Receipt expiry bypass

**Threat:** An old governance receipt (issued for a previous state of the
codebase or agent configuration) is presented as current authorisation.

**Mitigation:** The replay verifier checks `stored["expires_at"] > check_at`
as a pre-replay structural check.  An expired receipt yields `DENY` with
reason code `RECEIPT_EXPIRED`.

**Demonstrated in:** `TestReceiptFreshness.test_expired_receipt_returns_deny`

---

## Threats Intentionally Not Solved

The following threats are outside the scope of this repository and are not
mitigated by any code here.

### Kernel compromise or container escape

If the operating system kernel is compromised, or if the process running this
code escapes its container, all security properties modelled here are void.
OS-level isolation is a deployment concern, not a governance-logic concern.

### Malicious Python runtime

If the Python interpreter itself is malicious — modified to return different
values from hashing functions, skip predicate evaluations, or inject fields
into dicts — the governance stack cannot detect this.  The governance logic
assumes the Python runtime is honest.

### Hostile OS or hardware

Memory extraction, speculative execution side-channels, rowhammer, or
malicious firmware can compromise process state without being visible to
application-layer code.  These are hardware and OS concerns.

### Real-time distributed clock integrity

The demo uses fixed constant timestamps.  A production system that derives
`check_at` from a wall-clock source is vulnerable to clock skew, NTP
manipulation, or time-of-check/time-of-use races.  Solving this requires
a trusted time source with cryptographic provenance (e.g., RFC 8915
NTS-secured NTP, or a hardware RTC with attestation).

### Cryptographic key theft

The demo uses SHA-256 for receipt hashing but does not sign receipts.  A
production system that signs receipts is vulnerable to signing key theft.
Key protection requires HSM storage, access controls, and key rotation
procedures.

### Race conditions in concurrent evaluation

The governance stack is implemented as pure functions with no shared mutable
state.  However, if multiple concurrent evaluations share a mutable `intent`
dict (modified between layer evaluations), the defence-in-depth re-validation
in Layer 2 may observe a different intent than Layer 1 saw.  This is a
caller-side invariant, not a governance-stack invariant.

### Source file modification during replay

The replay verifier assumes that the source code executing during replay is
identical to the source code that produced the original receipt.  If the
governance rules have been modified between issuance and replay, the
recomputed receipt will differ from the stored receipt — but this is
indistinguishable from deliberate tampering.  Policy versioning (see
[ARCHITECTURE.md — Productionization](ARCHITECTURE.md#productionization)) is
required to manage this correctly.

---

## Security Assumptions

The following properties are assumed to hold; the governance logic does not
verify them.

1. **Deterministic hashing is trusted.** `hashlib.sha256` behaves correctly
   and is not manipulated.

2. **Python runtime behaves honestly.** Dict operations, string comparisons,
   and boolean evaluations return correct results.

3. **Source files are not modified between issuance and replay.** If the
   governance rule source changes between these two events, the replay result
   may differ from the original decision for reasons unrelated to tampering.
   This is an operational concern, not a code defect.

4. **Demo timestamps are constants.** `DEMO_ISSUED_AT`, `DEMO_EXPIRES_AT`, and
   `DEMO_CHECK_AT` are string literals in source code.  They do not reflect
   real calendar time and do not constitute real-time access control.

5. **The caller supplies honest raw inputs to the replay verifier.** If the
   caller supplies different raw inputs to the replay verifier than were used
   at issuance, the mismatch will be detected (the receipt will fail), but the
   governance stack cannot determine which set of inputs is authentic.  Input
   provenance is a caller concern.

---

## Boundary Statement

**The governance logic modelled in this repository is not itself execution
authority.**

A receipt carrying `INTENT_ADVISORY_ACCEPTED` or `PREFLIGHT_ADVISORY_ACCEPTED`
is evidence that the governance stack evaluated a proposal and found it within
policy.  It is not a permission token.  It does not grant, delegate, or imply
any authority to perform the evaluated action.

The execution boundary — the point at which a real action would be taken — is
external to this codebase and is not modelled here.  Any system that treats
a governance receipt as sufficient authorisation to execute without an
additional verification step at the execution boundary has introduced a trust
assumption that this codebase does not support.

---

## Known Limitations

### Regex-based deny-list

The command deny-list operates on the string representation of the proposed
command.  It is susceptible to obfuscation, encoding tricks, shell expansion,
and command composition patterns not anticipated by the patterns.  It is
illustrative, not a production security control.

See [ARCHITECTURE.md — Deny-list Limitations](ARCHITECTURE.md#deny-list-limitations)
for a detailed discussion.

### Caller-supplied timestamps in demo mode

`DEMO_CHECK_AT` is a module-level constant, not a trusted clock source.
The `check_at` parameter of `verify_preflight_replay` is supplied by the
caller.  A caller can supply any string as `check_at`, bypassing the expiry
check.  In production, `check_at` must be derived from a trusted, verifiable
clock source and must not be under the control of the party presenting the
receipt.

### No cryptographic signatures

Receipts are hash-committed but not signed.  A SHA-256 hash proves internal
consistency but not issuer identity.  An attacker who can execute arbitrary
code in the governance process can produce a receipt with any hash.
Signing receipts with a private key stored in an HSM would bind each receipt
to a verifiable issuer identity.

### No hardware root of trust

Nothing in this codebase is backed by a hardware security module, trusted
platform module, or secure enclave.  The security properties are entirely
software-layer claims.

### No real sandbox

The governance stack evaluates proposals in the same process and OS context
as all other Python code.  There is no isolation between the governance
evaluator and the broader execution environment.  A sandboxed governance
evaluator would run in a separate process with minimal capabilities,
no network access, and a read-only view of the governance rule source.

### Single-layer reject-on-first-failure

The validation functions collect all failing checks and return all reason
codes, but a `DENY` decision is binary.  There is no partial-acceptance
mechanism, no escalation path from `DENY` to `REQUIRE_HUMAN_APPROVAL` for
borderline cases, and no policy-configurable override.  These would be
required in a production system with non-binary risk classifications.
