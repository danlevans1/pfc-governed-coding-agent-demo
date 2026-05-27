DENY = "DENY"
REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
ALLOW = "ALLOW"


def build_decision(
    gate_name: str,
    decision: str,
    reasons: list[str] | None = None,
    checks: dict | None = None,
    **fields,
) -> dict:
    return {
        "gate_name": gate_name,
        "decision": decision,
        "reason": " ".join(reasons or []),
        "checks": checks or {},
        **fields,
    }


def deny(gate_name: str, reasons: list[str] | None = None, checks: dict | None = None, **fields) -> dict:
    return build_decision(gate_name, DENY, reasons, checks, **fields)


def require_human_approval(
    gate_name: str,
    reasons: list[str] | None = None,
    checks: dict | None = None,
    **fields,
) -> dict:
    return build_decision(gate_name, REQUIRE_HUMAN_APPROVAL, reasons, checks, **fields)


def allow(gate_name: str, reasons: list[str] | None = None, checks: dict | None = None, **fields) -> dict:
    return build_decision(gate_name, ALLOW, reasons, checks, **fields)
