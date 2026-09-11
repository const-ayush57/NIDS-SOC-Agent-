"""
Firewall Mitigation Tool
Accepts an attack type and a source IP address, then generates an iptables
bash script to isolate or rate-limit the malicious traffic.

Deterministic rule logic:
  - DoS    → rate-limit SYN packets + drop the rest
  - Probe / R2L / U2R → full DROP
  - Normal → no rule required
"""

from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

class FirewallMitigationResult(BaseModel):
    """Result returned by the firewall mitigation tool."""

    attack_type: str = Field(description="Canonical attack type resolved from the input string")
    source_ip: str = Field(description="Source IP address targeted by the rule")
    iptables_script: str = Field(
        description="Ready-to-run iptables bash script for the given attack and IP"
    )
    rule_applied: bool = Field(
        description="True if a blocking/rate-limiting rule was generated; False for Normal traffic"
    )
    explanation: str = Field(
        description="Human-readable explanation of the generated firewall rule"
    )


# ---------------------------------------------------------------------------
# Rule explanations
# ---------------------------------------------------------------------------

_EXPLANATIONS: dict[str, str] = {
    "DoS": (
        "Rate-limits inbound TCP SYN packets from {ip} to 1 per second to absorb "
        "burst floods while allowing legitimate slow connections. All remaining "
        "packets from {ip} are dropped to stop the denial-of-service attack."
    ),
    "Probe": (
        "Drops all inbound packets from {ip} unconditionally. Port-scan/reconnaissance "
        "traffic has no legitimate purpose from this source and blocking it prevents "
        "the attacker from mapping open services for follow-on exploitation."
    ),
    "R2L": (
        "Drops all inbound packets from {ip} unconditionally. Remote-to-local "
        "exploitation attempts indicate an active credential or service attack; "
        "full isolation prevents further unauthorised access."
    ),
    "U2R": (
        "Drops all inbound packets from {ip} unconditionally. User-to-root "
        "privilege escalation traffic from an external source indicates active "
        "exploitation; immediate isolation limits lateral movement."
    ),
    "Normal": (
        "No iptables rule is required. Traffic from {ip} is classified as Normal "
        "and no blocking action should be applied."
    ),
}

# Aliases mirror those in threat_intel_rag.py for consistency
_ALIASES: dict[str, str] = {
    "dos": "DoS",
    "denial of service": "DoS",
    "network denial of service": "DoS",
    "probe": "Probe",
    "port scan": "Probe",
    "reconnaissance": "Probe",
    "r2l": "R2L",
    "remote to local": "R2L",
    "remote-to-local": "R2L",
    "u2r": "U2R",
    "user to root": "U2R",
    "user-to-root": "U2R",
    "privilege escalation": "U2R",
    "normal": "Normal",
    "benign": "Normal",
    "clean": "Normal",
}

_KNOWN = {"DoS", "Probe", "R2L", "U2R", "Normal"}


def _resolve(attack_type: str) -> str:
    """Normalise input to a canonical attack category."""
    # Strip common LLM-generated prefixes (e.g. "Threat Classification: DoS")
    cleaned = attack_type.replace("Threat Classification:", "").strip()
    for known in _KNOWN:
        if cleaned.lower() == known.lower():
            return known
    return _ALIASES.get(cleaned.lower(), cleaned)


# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------

@tool(permission=ToolPermission.READ_WRITE)
def generate_firewall_mitigation(attack_type: str, source_ip: str) -> FirewallMitigationResult:
    """
    Generate an iptables Linux firewall rule to isolate or rate-limit malicious traffic.

    Applies deterministic rule logic based on the NSL-KDD attack category:
      - DoS   : rate-limit TCP SYN to 1/s then DROP remaining packets from source IP
      - Probe : DROP all packets from source IP
      - R2L   : DROP all packets from source IP
      - U2R   : DROP all packets from source IP
      - Normal: no rule required

    Args:
        attack_type (str): The attack or threat category string (e.g. "DoS", "Probe",
            "R2L", "U2R", "Normal"). Common aliases and LLM-prefixed strings such as
            "Threat Classification: DoS" are accepted.
        source_ip (str): The IPv4 address of the malicious or suspicious source host.

    Returns:
        FirewallMitigationResult: Contains the resolved attack type, source IP,
            ready-to-run iptables bash script, a flag indicating whether a blocking
            rule was generated, and a plain-English explanation.
    """
    resolved = _resolve(attack_type)

    if resolved == "DoS":
        script = (
            f"iptables -A INPUT -s {source_ip} -p tcp --syn -m limit --limit 1/s -j ACCEPT\n"
            f"iptables -A INPUT -s {source_ip} -j DROP"
        )
        rule_applied = True
    elif resolved in ("Probe", "R2L", "U2R"):
        script = f"iptables -A INPUT -s {source_ip} -j DROP"
        rule_applied = True
    else:
        script = "# No block rule required. Traffic classified as Normal."
        rule_applied = False

    explanation = _EXPLANATIONS.get(
        resolved,
        f"Unrecognised attack type '{resolved}'. Manual review recommended.",
    ).format(ip=source_ip)

    return FirewallMitigationResult(
        attack_type=resolved,
        source_ip=source_ip,
        iptables_script=script,
        rule_applied=rule_applied,
        explanation=explanation,
    )
