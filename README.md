# NIDS – Network Intrusion Detection System (watsonx Orchestrate)

## Overview

This project implements a **Network Intrusion Detection System (NIDS)** as a watsonx Orchestrate native agent solution. It combines an IBM watsonx.ai Llama-3-70B classifier with a structured SOC investigation flow to detect, triage, and report on potential network intrusions in real time.

### Key Features

- **NIDS Classifier Tool** – classifies raw packet metrics into threat categories (DoS, Probe, R2L, U2R, Normal)
- **SOC Investigation Flow** – two-stage flow: packet classification → detailed investigation report generation
- **NIDS Agent** – conversational SOC assistant that guides analysts through threat analysis

---

## Architecture Diagram

```mermaid
graph TB
    User[SOC Analyst / User] -->|Provides packet metrics| Agent[nids_agent]

    Agent -->|Quick classify| ClassifyTool[classify_network_packet\ntool]
    Agent -->|Full investigation| Flow[soc_investigation_flow\nflow tool]

    Flow -->|Step 1 – classify| ClassifyTool
    Flow -->|Step 2 – generate report| LLM[LLM Prompt Node\nmeta-llama/llama-3-3-70b-instruct]

    ClassifyTool -->|REST call| WatsonX[IBM watsonx.ai\neu-gb endpoint]
    LLM -->|Built-in wxO model| WatsonX

    WatsonX -->|ClassificationResult| Flow
    LLM -->|SOCInvestigationReport| Flow
    Flow -->|Full report| Agent
    Agent -->|Presents findings| User

    style Agent fill:#4A90E2,stroke:#2E5C8A,color:#fff
    style Flow fill:#50C878,stroke:#2E7D4E,color:#fff
    style ClassifyTool fill:#F39C12,stroke:#C87F0A,color:#fff
    style LLM fill:#9B59B6,stroke:#7D3C98,color:#fff
    style WatsonX fill:#E74C3C,stroke:#C0392B,color:#fff
```

---

## SOC Investigation Flow Diagram

```mermaid
flowchart TD
    Start([START]) --> Classify["classify_network_packet\n(NIDS Classifier Tool)\n\nInputs: duration, src_bytes,\ndst_bytes, count, srv_count"]

    Classify --> Report["generate_soc_report\n(LLM Prompt Node)\n\nSynthesises classification result\ninto a full SOC report"]

    Report --> End([END])

    Classify -.->|ClassificationResult| Report

    style Start fill:#2ECC71,stroke:#27AE60,color:#fff
    style End fill:#E74C3C,stroke:#C0392B,color:#fff
    style Classify fill:#F39C12,stroke:#D68910,color:#fff
    style Report fill:#9B59B6,stroke:#7D3C98,color:#fff
```

---

## Project Structure

```
NIDS/
├── __init__.py
├── main_flow.py                  # Programmatic test harness
├── import-all.sh                 # CLI import script
├── README.md
│
├── tools/
│   ├── __init__.py
│   └── nids_classifier.py        # @tool – classify_network_packet
│
├── flows/
│   ├── __init__.py
│   └── soc_investigation_flow.py # @flow – soc_investigation_flow
│
├── agents/
│   └── nids_agent.yaml           # Native agent configuration
│
└── generated/
    └── soc_investigation_flow.json  # Compiled flow spec (auto-generated)
```

---

## Tools & Flows

### `classify_network_packet` (Python Tool)

Accepts five NSL-KDD-style packet metrics and returns a [`ClassificationResult`](tools/nids_classifier.py).

| Parameter   | Type    | Description |
|-------------|---------|-------------|
| `duration`  | `float` | Connection length in seconds |
| `src_bytes` | `int`   | Bytes from source → destination |
| `dst_bytes` | `int`   | Bytes from destination → source |
| `count`     | `int`   | Connections to same host / 2 s |
| `srv_count` | `int`   | Connections to same service / 2 s |

**Output fields:** `threat_detected`, `threat_level`, `attack_type`, `confidence_score`, `summary`, `recommendations`

---

### `soc_investigation_flow` (Flow Tool)

Full SOC investigation in two steps:

1. **Classify** – invokes `classify_network_packet`
2. **Report** – LLM prompt node generates a `SOCInvestigationReport`

**Output fields:** `executive_summary`, `threat_assessment`, `ioc_analysis`, `mitigation_steps`, `escalation_required`, `ticket_priority`

---

## Configuration

| Setting | Value |
|---------|-------|
| **watsonx.ai endpoint** | `https://eu-gb.ml.cloud.ibm.com/ml/v1/text/chat?version=2023-05-29` |
| **Model** | `meta-llama/llama-3-3-70b-instruct` |
| **Project ID** | `b5711429-279d-45a1-a962-8db58d7bee19` |

> **Security note:** Store your API key in an environment variable `WATSONX_API_KEY` rather than hard-coding it.
> ```bash
> export WATSONX_API_KEY="<your-key>"
> export WATSONX_PROJECT_ID="b5711429-279d-45a1-a962-8db58d7bee19"
> ```

---

## Usage

### 1. Import into watsonx Orchestrate

```bash
chmod +x import-all.sh
./import-all.sh
```

### 2. Launch the chat UI

```bash
orchestrate chat start
# Select: nids_agent
```

### 3. Test programmatically

```bash
export PYTHONPATH=/path/to/ibm-watsonx-orchestrate-adk/src:/path/to/ibm-watsonx-orchestrate-adk
python3 main_flow.py
```

---

## Example Interactions

**Quick classification:**
```
Classify this connection — duration: 0, src_bytes: 491, dst_bytes: 0, count: 2, srv_count: 2
```

**Full SOC investigation:**
```
Run a full SOC investigation for — duration: 0, src_bytes: 0, dst_bytes: 0, count: 511, srv_count: 511
```

**Normal traffic baseline:**
```
Classify this connection — duration: 8, src_bytes: 181, dst_bytes: 5450, count: 8, srv_count: 8
```

---

## Threat Level Reference

| Level      | Description                                          | SOC Action |
|------------|------------------------------------------------------|------------|
| `CRITICAL` | Active intrusion / exploit confirmed                 | Immediate escalation (P1) |
| `HIGH`     | Strong indicators of compromise                      | Escalate to Tier-2 (P2) |
| `MEDIUM`   | Suspicious activity, possible reconnaissance         | Investigate (P3) |
| `LOW`      | Minor anomaly, likely benign                         | Monitor (P4) |
| `NORMAL`   | No threat detected                                   | No action required |

---

## Prerequisites

- IBM watsonx Orchestrate CLI (`orchestrate`)
- Python ≥ 3.10
- `ibm_watsonx_orchestrate` ADK package
- `pydantic` ≥ 2.0

## License

MIT
