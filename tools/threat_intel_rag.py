"""
Threat Intelligence RAG Tool
Accepts a threat classification string and returns the corresponding MITRE ATT&CK
mitigation strategy using a simulated knowledge base, optionally enriched by the
watsonx.ai Llama-3 model for contextual elaboration.
"""

from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
from pydantic import BaseModel, Field
from typing import Optional
import os
import json
import urllib.request
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Simulated MITRE ATT&CK Knowledge Base
# Maps attack/threat categories to structured mitigation entries.
# Each entry follows the MITRE ATT&CK mitigation schema.
# ---------------------------------------------------------------------------

_MITRE_KB: dict[str, dict] = {
    "DoS": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "mitre_mitigations": [
            {
                "mitigation_id": "M1037",
                "mitigation_name": "Filter Network Traffic",
                "description": (
                    "Use network appliances or cloud provider controls to filter "
                    "inbound traffic and block known attack sources. Deploy "
                    "rate-limiting rules on edge routers and firewalls."
                ),
            },
            {
                "mitigation_id": "M1035",
                "mitigation_name": "Limit Access to Resource Over Network",
                "description": (
                    "Restrict access to services to only trusted IP ranges. "
                    "Use anycast network diffusion to distribute attack traffic "
                    "across multiple scrubbing centres."
                ),
            },
        ],
        "detection_tips": (
            "Monitor for unusual spikes in inbound connection counts, "
            "high srv_count values, or sudden drops in legitimate traffic. "
            "Alert when count or srv_count exceed established baselines."
        ),
        "soc_priority": "P1 – Immediate containment required",
    },
    "Probe": {
        "tactic": "Reconnaissance",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "mitre_mitigations": [
            {
                "mitigation_id": "M1031",
                "mitigation_name": "Network Intrusion Prevention",
                "description": (
                    "Use an IDS/IPS with signatures for common port-scanning tools "
                    "(nmap, masscan). Block sequential port-scan patterns at the "
                    "perimeter firewall."
                ),
            },
            {
                "mitigation_id": "M1030",
                "mitigation_name": "Network Segmentation",
                "description": (
                    "Segment the network so that internal hosts are not directly "
                    "reachable from untrusted zones. Use DMZ architectures and "
                    "micro-segmentation to limit lateral movement opportunities "
                    "discovered during reconnaissance."
                ),
            },
        ],
        "detection_tips": (
            "Detect sequential or rapid connection attempts to multiple ports "
            "from a single source. A low duration with moderate src_bytes and "
            "zero dst_bytes is a strong Probe indicator."
        ),
        "soc_priority": "P2 – Investigate and isolate scanning source",
    },
    "R2L": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts (Remote-to-Local exploitation)",
        "mitre_mitigations": [
            {
                "mitigation_id": "M1032",
                "mitigation_name": "Multi-factor Authentication",
                "description": (
                    "Enforce MFA on all remote-access entry points including VPN, "
                    "SSH, and web portals to prevent unauthorised remote logins "
                    "even when credentials are compromised."
                ),
            },
            {
                "mitigation_id": "M1027",
                "mitigation_name": "Password Policies",
                "description": (
                    "Enforce strong password policies and credential rotation. "
                    "Monitor for brute-force attempts and lock accounts after "
                    "repeated failures. Use a PAM solution for privileged access."
                ),
            },
            {
                "mitigation_id": "M1026",
                "mitigation_name": "Privileged Account Management",
                "description": (
                    "Limit the number of accounts with remote administrative "
                    "privileges. Audit all remote-access sessions and alert on "
                    "anomalous login times or source IPs."
                ),
            },
        ],
        "detection_tips": (
            "Look for connections with high dst_bytes relative to src_bytes from "
            "external sources, indicating data being pulled to a remote host. "
            "Correlate with authentication log failures."
        ),
        "soc_priority": "P1 – Possible credential compromise; escalate immediately",
    },
    "U2R": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "mitre_mitigations": [
            {
                "mitigation_id": "M1048",
                "mitigation_name": "Application Isolation and Sandboxing",
                "description": (
                    "Run applications and services in isolated sandboxes or "
                    "containers with minimal privileges to limit the impact of "
                    "successful local exploits."
                ),
            },
            {
                "mitigation_id": "M1051",
                "mitigation_name": "Update Software",
                "description": (
                    "Maintain up-to-date patches for the OS kernel and all "
                    "user-space applications. Subscribe to vendor security "
                    "advisories and apply critical patches within the SLA window."
                ),
            },
            {
                "mitigation_id": "M1038",
                "mitigation_name": "Execution Prevention",
                "description": (
                    "Use application allow-listing to prevent unauthorised binaries "
                    "from executing. Enable SELinux/AppArmor mandatory access "
                    "controls to restrict privilege escalation paths."
                ),
            },
        ],
        "detection_tips": (
            "Alert on processes spawning shells or gaining root/SYSTEM privileges "
            "from non-privileged contexts. Monitor for unusual SUID/SGID binary "
            "execution or unexpected kernel module loads."
        ),
        "soc_priority": "P1 – Active exploitation suspected; isolate host",
    },
    "Normal": {
        "tactic": "N/A",
        "technique_id": "N/A",
        "technique_name": "No malicious technique detected",
        "mitre_mitigations": [
            {
                "mitigation_id": "M1056",
                "mitigation_name": "Pre-compromise (Baseline Monitoring)",
                "description": (
                    "Continue baseline network monitoring to establish normal "
                    "traffic patterns. No immediate mitigation action required."
                ),
            }
        ],
        "detection_tips": "Traffic appears benign. Maintain standard monitoring posture.",
        "soc_priority": "P4 – No action required",
    },
}

# Aliases to handle slight variations in classification strings
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


def _resolve_classification(classification: str) -> str:
    """Normalise an input classification string to a known KB key."""
    key = classification.strip().lower()
    # Direct case-insensitive match first
    for kb_key in _MITRE_KB:
        if key == kb_key.lower():
            return kb_key
    # Alias lookup
    return _ALIASES.get(key, "Unknown")


def _call_watsonx_elaboration(classification: str, kb_entry: dict) -> str:
    """
    Ask the LLM to produce a concise elaboration of the KB mitigation entry.
    Returns the raw elaboration string, or an empty string on failure.
    """
    api_key = os.environ.get("WATSONX_API_KEY") or os.environ.get("IBM_API_KEY", "")
    project_id = os.environ.get("WATSONX_PROJECT_ID", "b5711429-279d-45a1-a962-8db58d7bee19")
    url = "https://eu-gb.ml.cloud.ibm.com/ml/v1/text/chat?version=2023-05-29"

    mitigations_text = "\n".join(
        f"- [{m['mitigation_id']}] {m['mitigation_name']}: {m['description']}"
        for m in kb_entry["mitre_mitigations"]
    )

    system_prompt = (
        "You are a senior cybersecurity analyst specialising in MITRE ATT&CK threat intelligence. "
        "Given a threat classification and its baseline MITRE mitigations, write a concise 3-5 sentence "
        "operational elaboration that a SOC analyst can act on immediately. "
        "Be specific, technical, and actionable. Do NOT repeat the mitigation text verbatim."
    )
    user_prompt = (
        f"Threat classification: {classification}\n"
        f"MITRE Tactic: {kb_entry['tactic']} | Technique: {kb_entry['technique_id']} – {kb_entry['technique_name']}\n\n"
        f"Baseline mitigations:\n{mitigations_text}\n\n"
        "Provide your operational elaboration:"
    )

    payload = json.dumps({
        "model_id": "meta-llama/llama-3-3-70b-instruct",
        "project_id": project_id,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 300,
        "temperature": 0.2,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body["choices"][0]["message"]["content"].strip()
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

class MitreMitigation(BaseModel):
    """A single MITRE ATT&CK mitigation entry."""

    mitigation_id: str = Field(description="MITRE mitigation identifier (e.g. M1037)")
    mitigation_name: str = Field(description="Human-readable name of the mitigation control")
    description: str = Field(description="Detailed description of the mitigation action")


class ThreatIntelResult(BaseModel):
    """Full MITRE ATT&CK intelligence result for a given threat classification."""

    resolved_classification: str = Field(
        description="Canonical threat category resolved from the input string"
    )
    tactic: str = Field(description="MITRE ATT&CK tactic associated with the threat")
    technique_id: str = Field(description="MITRE ATT&CK technique identifier")
    technique_name: str = Field(description="Human-readable technique name")
    mitigations: list[MitreMitigation] = Field(
        description="List of applicable MITRE ATT&CK mitigation controls"
    )
    detection_tips: str = Field(
        description="SOC detection guidance based on network traffic indicators"
    )
    soc_priority: str = Field(description="Suggested SOC response priority and immediate action")
    llm_elaboration: str = Field(
        description="LLM-generated operational elaboration of the mitigation strategy"
    )
    kb_hit: bool = Field(
        description="True if the classification matched a known entry in the knowledge base"
    )


# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------

@tool(permission=ToolPermission.READ_ONLY)
def get_threat_intel(threat_classification: str) -> ThreatIntelResult:
    """
    Look up the MITRE ATT&CK mitigation strategy for a given threat classification.

    Uses a simulated threat intelligence knowledge base keyed on NSL-KDD attack
    categories (DoS, Probe, R2L, U2R, Normal). For known classifications the tool
    returns structured MITRE mitigations and detection tips, then enriches the
    response with an LLM-generated operational elaboration via watsonx.ai.

    Args:
        threat_classification (str): The threat or attack category string to look up.
            Accepted values (case-insensitive): DoS, Probe, R2L, U2R, Normal,
            and common aliases such as "denial of service", "port scan",
            "privilege escalation", "remote-to-local", etc.

    Returns:
        ThreatIntelResult: Structured MITRE ATT&CK intelligence including tactic,
            technique, mitigation controls, detection tips, SOC priority, and an
            LLM-generated operational elaboration.
    """
    resolved = _resolve_classification(threat_classification)
    kb_hit = resolved in _MITRE_KB

    if not kb_hit:
        # Return a safe fallback for unknown classifications
        return ThreatIntelResult(
            resolved_classification=threat_classification,
            tactic="Unknown",
            technique_id="N/A",
            technique_name="Unrecognised threat category",
            mitigations=[
                MitreMitigation(
                    mitigation_id="N/A",
                    mitigation_name="Manual Review Required",
                    description=(
                        "The supplied classification could not be matched to a known "
                        "MITRE ATT&CK category. A senior analyst should review the raw "
                        "network metrics and classify the traffic manually."
                    ),
                )
            ],
            detection_tips="Conduct manual packet analysis and cross-reference with threat feeds.",
            soc_priority="P3 – Manual triage required",
            llm_elaboration="",
            kb_hit=False,
        )

    entry = _MITRE_KB[resolved]

    # Build structured mitigations list
    mitigations = [
        MitreMitigation(
            mitigation_id=m["mitigation_id"],
            mitigation_name=m["mitigation_name"],
            description=m["description"],
        )
        for m in entry["mitre_mitigations"]
    ]

    # Enrich with LLM elaboration (best-effort; silent on failure)
    elaboration = _call_watsonx_elaboration(resolved, entry)

    return ThreatIntelResult(
        resolved_classification=resolved,
        tactic=entry["tactic"],
        technique_id=entry["technique_id"],
        technique_name=entry["technique_name"],
        mitigations=mitigations,
        detection_tips=entry["detection_tips"],
        soc_priority=entry["soc_priority"],
        llm_elaboration=elaboration,
        kb_hit=True,
    )
