"""
SOC Investigation Flow  (v2)
Orchestrates a full, end-to-end SOC investigation for a suspicious network
connection by chaining all four NIDS tools in sequence:

  Step 1 – classify_network_packet
           Classify packet metrics → ClassificationResult
             (threat_detected, threat_level, attack_type, confidence_score,
              summary, recommendations)

  Step 2 – get_threat_intel
           Query MITRE ATT&CK KB with attack_type → ThreatIntelResult
             (tactic, technique_id, technique_name, mitigations,
              detection_tips, soc_priority, llm_elaboration, kb_hit)

  Step 3 – generate_firewall_mitigation
           Build iptables script from attack_type + source_ip
             → FirewallMitigationResult
             (iptables_script, rule_applied, explanation)

  Step 4 – validate_safety_policy
           Check the iptables script against protected-IP policy
             → PolicyGuardResult
             (passed, violation_reason, validated_script, offending_ips)

  Step 5 – LLM prompt node
           Synthesise all four outputs into a final SafeIncidentReport
"""

from pydantic import BaseModel, Field
from ibm_watsonx_orchestrate.flow_builder.flows import Flow, flow, START, END

from tools.nids_classifier import classify_network_packet
from tools.threat_intel_rag import get_threat_intel
from tools.firewall_mitigation import generate_firewall_mitigation
from tools.policy_guard import validate_safety_policy


# ---------------------------------------------------------------------------
# Flow input schema
# ---------------------------------------------------------------------------

class SOCInvestigationInput(BaseModel):
    """Input parameters for the SOC investigation flow."""

    duration: float = Field(description="Length of the network connection in seconds.")
    src_bytes: int = Field(description="Number of data bytes sent from source to destination.")
    dst_bytes: int = Field(description="Number of data bytes sent from destination to source.")
    count: int = Field(description="Number of connections to the same host in the past 2 seconds.")
    srv_count: int = Field(description="Number of connections to the same service in the past 2 seconds.")
    source_ip: str = Field(
        default="0.0.0.0",
        description="Source IPv4 address of the connection under investigation.",
    )


# ---------------------------------------------------------------------------
# Final report output schema
# ---------------------------------------------------------------------------

class SafeIncidentReport(BaseModel):
    """Final validated SOC incident report produced by the investigation flow."""

    incident_id: str = Field(description="Auto-generated incident reference (e.g. INC-20240101-001).")
    executive_summary: str = Field(description="High-level summary of the investigation for management.")
    threat_classification: str = Field(description="Resolved attack category (DoS / Probe / R2L / U2R / Normal).")
    threat_level: str = Field(description="Severity level: CRITICAL | HIGH | MEDIUM | LOW | NORMAL.")
    mitre_tactic: str = Field(description="MITRE ATT&CK tactic associated with the detected threat.")
    mitre_technique: str = Field(description="MITRE ATT&CK technique ID and name.")
    mitre_mitigations_summary: str = Field(description="Plain-English summary of applicable MITRE mitigations.")
    firewall_action: str = Field(description="The validated iptables rule (or override message) ready for deployment.")
    firewall_policy_passed: bool = Field(description="True if the firewall rule cleared the enterprise safety policy.")
    escalation_required: bool = Field(description="True if the incident must be escalated to Tier-2 SOC.")
    ticket_priority: str = Field(description="Suggested ITSM ticket priority: P1 | P2 | P3 | P4.")
    analyst_notes: str = Field(description="Additional detection tips and recommended follow-up actions.")


# ---------------------------------------------------------------------------
# Flow definition
# ---------------------------------------------------------------------------

@flow(
    name="soc_investigation_flow",
    display_name="SOC Investigation Flow",
    description=(
        "End-to-end SOC investigation pipeline: classifies network packet metrics, "
        "queries the MITRE ATT&CK knowledge base, generates an iptables firewall rule, "
        "validates the rule against enterprise safety policy, and produces a final "
        "safe incident report."
    ),
    input_schema=SOCInvestigationInput,
)
def build_soc_investigation_flow(aflow: Flow) -> Flow:
    """
    Build the full SOC investigation flow.

    Sequence:
      START
        → step1_classify      (classify_network_packet tool)
        → step2_threat_intel  (get_threat_intel tool)
        → step3_firewall      (generate_firewall_mitigation tool)
        → step4_policy_guard  (validate_safety_policy tool)
        → step5_report        (LLM prompt node — SafeIncidentReport)
        → END
    """

    # ------------------------------------------------------------------
    # Step 1 – Classify the network packet
    # Input  : duration, src_bytes, dst_bytes, count, srv_count  (flow input)
    # Output : threat_detected, threat_level, attack_type,
    #          confidence_score, summary, recommendations
    # ------------------------------------------------------------------
    step1_classify = aflow.tool(classify_network_packet)

    # ------------------------------------------------------------------
    # Step 2 – Query MITRE ATT&CK knowledge base
    # Input  : threat_classification = attack_type  (from step 1)
    # Output : tactic, technique_id, technique_name, mitigations[],
    #          detection_tips, soc_priority, llm_elaboration, kb_hit
    # ------------------------------------------------------------------
    step2_threat_intel = aflow.tool(get_threat_intel)

    # ------------------------------------------------------------------
    # Step 3 – Generate iptables firewall rule
    # Input  : attack_type  (from step 1), source_ip  (flow input)
    # Output : iptables_script, rule_applied, explanation
    # ------------------------------------------------------------------
    step3_firewall = aflow.tool(generate_firewall_mitigation)

    # ------------------------------------------------------------------
    # Step 4 – Validate the firewall script against safety policy
    # Input  : firewall_script = iptables_script  (from step 3)
    # Output : passed, violation_reason, validated_script, offending_ips
    # ------------------------------------------------------------------
    step4_policy_guard = aflow.tool(validate_safety_policy)

    # ------------------------------------------------------------------
    # Step 5 – LLM prompt node: synthesise all outputs into a final
    #           SafeIncidentReport
    # ------------------------------------------------------------------
    step5_report = aflow.prompt(
        name="generate_safe_incident_report",
        system_prompt=[
            "You are a senior Tier-2 SOC analyst. "
            "Your task is to consolidate the outputs of four automated pipeline stages "
            "into a single, authoritative SafeIncidentReport. "
            "Be concise, factual, and actionable. "
            "Respond ONLY with a valid JSON object that matches the SafeIncidentReport schema exactly."
        ],
        user_prompt=[
            "=== STEP 1: NIDS CLASSIFICATION ===\n"
            "Threat detected   : {threat_detected}\n"
            "Threat level      : {threat_level}\n"
            "Attack type       : {attack_type}\n"
            "Confidence score  : {confidence_score}\n"
            "Classifier summary: {summary}\n"
            "Recommendations   : {recommendations}\n\n"

            "=== STEP 2: MITRE ATT&CK INTELLIGENCE ===\n"
            "Tactic            : {tactic}\n"
            "Technique         : {technique_id} – {technique_name}\n"
            "Detection tips    : {detection_tips}\n"
            "SOC priority      : {soc_priority}\n"
            "LLM elaboration   : {llm_elaboration}\n\n"

            "=== STEP 3: FIREWALL RULE GENERATED ===\n"
            "Source IP         : {source_ip}\n"
            "Rule applied      : {rule_applied}\n"
            "iptables script   :\n{iptables_script}\n"
            "Explanation       : {explanation}\n\n"

            "=== STEP 4: POLICY GUARD VALIDATION ===\n"
            "Policy passed     : {passed}\n"
            "Violation reason  : {violation_reason}\n"
            "Validated script  :\n{validated_script}\n\n"

            "=== ORIGINAL CONNECTION METRICS ===\n"
            "Duration: {duration}s | src_bytes: {src_bytes} | dst_bytes: {dst_bytes} "
            "| count: {count} | srv_count: {srv_count}\n\n"

            "Produce the final SafeIncidentReport JSON."
        ],
        llm="watsonx/meta-llama/llama-3-3-70b-instruct",
        input_schema=SOCInvestigationInput,
        output_schema=SafeIncidentReport,
    )

    # ------------------------------------------------------------------
    # Wire the full sequential pipeline
    # ------------------------------------------------------------------
    aflow.sequence(
        START,
        step1_classify,
        step2_threat_intel,
        step3_firewall,
        step4_policy_guard,
        step5_report,
        END,
    )
    return aflow
