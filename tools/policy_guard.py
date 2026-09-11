"""
Policy Guard Tool
Validates a generated firewall script against enterprise safety policies to
prevent accidental blocking of critical internal infrastructure.

Compliance logic (deterministic — no LLM involvement):
  - If the script targets any protected IP or subnet, block the action and
    return a safe override message.
  - Otherwise, append a GUARDIAN AGENT validation stamp and return the script.
"""

from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
from pydantic import BaseModel, Field
import ipaddress


# ---------------------------------------------------------------------------
# Protected IP / subnet list
# Any script that references one of these addresses will be rejected.
# ---------------------------------------------------------------------------

_CRITICAL_IPS: list[str] = [
    "192.168.0.1",
    "10.0.0.1",
    "127.0.0.1",
    "0.0.0.0",
]

_CRITICAL_SUBNETS: list[str] = [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "127.0.0.0/8",
]


def _extract_ips(script: str) -> list[str]:
    """
    Pull every token from the script that looks like an IPv4 address.
    Simple token scan — sufficient for iptables rule lines.
    """
    found = []
    for token in script.split():
        token = token.strip("'\"#,;")
        try:
            ipaddress.IPv4Address(token)
            found.append(token)
        except ValueError:
            pass
    return found


def _is_protected(ip_str: str) -> tuple[bool, str]:
    """
    Return (True, reason) if ip_str falls within any protected range,
    (False, "") otherwise.
    """
    # Exact-match check (covers all entries in _CRITICAL_IPS)
    if ip_str in _CRITICAL_IPS:
        return True, f"exact match against critical IP {ip_str}"

    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False, ""

    for subnet_str in _CRITICAL_SUBNETS:
        try:
            if addr in ipaddress.IPv4Network(subnet_str, strict=False):
                return True, f"{ip_str} falls within protected subnet {subnet_str}"
        except ValueError:
            pass

    return False, ""


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

class PolicyGuardResult(BaseModel):
    """Result of the enterprise safety-policy validation."""

    passed: bool = Field(
        description="True if the script passed all policy checks; False if it was blocked"
    )
    violation_reason: str = Field(
        description="Human-readable reason for rejection, or empty string when the script passed"
    )
    validated_script: str = Field(
        description=(
            "The final firewall script: either the original script stamped by the "
            "GUARDIAN AGENT (passed) or a safe override comment (blocked)"
        )
    )
    offending_ips: list[str] = Field(
        description="List of protected IPs detected in the script that triggered the violation"
    )


# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------

@tool(permission=ToolPermission.READ_ONLY)
def validate_safety_policy(firewall_script: str) -> PolicyGuardResult:
    """
    Evaluate a firewall script against enterprise safety policies to prevent
    self-inflicted outages from blocking critical internal infrastructure.

    Protected addresses include individual critical IPs (192.168.0.1, 10.0.0.1,
    127.0.0.1, 0.0.0.0) and entire subnets (10.0.0.0/8, 192.168.0.0/16,
    172.16.0.0/12, 127.0.0.0/8). Any script targeting these is rejected and
    replaced with a safe override comment; compliant scripts receive a
    GUARDIAN AGENT validation stamp.

    Args:
        firewall_script (str): The iptables bash script produced by the
            generate_firewall_mitigation tool (or any other source).

    Returns:
        PolicyGuardResult: Validation outcome with passed flag, violation reason,
            list of offending IPs, and the final (safe) script.
    """
    extracted = _extract_ips(firewall_script)
    offending: list[str] = []
    reasons: list[str] = []

    for ip in extracted:
        protected, reason = _is_protected(ip)
        if protected:
            offending.append(ip)
            reasons.append(reason)

    if offending:
        # One violation is enough to block the entire script
        primary_ip = offending[0]
        primary_reason = reasons[0]
        override = (
            f"# BLOCKED BY GUARDIAN AGENT: Attempted to isolate critical infrastructure "
            f"IP ({primary_ip}). Action overridden."
        )
        return PolicyGuardResult(
            passed=False,
            violation_reason=primary_reason,
            validated_script=override,
            offending_ips=offending,
        )

    stamped = firewall_script + "\n# STATUS: VALIDATED BY GUARDIAN AGENT"
    return PolicyGuardResult(
        passed=True,
        violation_reason="",
        validated_script=stamped,
        offending_ips=[],
    )
