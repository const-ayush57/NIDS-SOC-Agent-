#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# import-all.sh – Import all NIDS tools, flows, and agents into watsonx Orchestrate
#
# Usage:
#   chmod +x import-all.sh
#   ./import-all.sh
#
# Prerequisites:
#   - IBM watsonx Orchestrate CLI installed and authenticated
#   - An environment must be active (local or production)
#     e.g.: orchestrate env activate local
# ---------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "=== NIDS: Importing Python tools ==="
for tool_file in nids_classifier.py threat_intel_rag.py firewall_mitigation.py policy_guard.py; do
  echo "  → Importing tool: ${tool_file}"
  orchestrate tools import -k python -f "${SCRIPT_DIR}/tools/${tool_file}"
done

echo ""
echo "=== NIDS: Importing Flow tools ==="
for flow_file in soc_investigation_flow.py; do
  echo "  → Importing flow: ${flow_file}"
  orchestrate tools import -k flow -f "${SCRIPT_DIR}/flows/${flow_file}"
done

echo ""
echo "=== NIDS: Importing Agents ==="
for agent_file in nids_agent.yaml; do
  echo "  → Importing agent: ${agent_file}"
  orchestrate agents import -f "${SCRIPT_DIR}/agents/${agent_file}"
done

echo ""
echo "✅  All NIDS components imported successfully."
echo "    Launch the chat UI with:  orchestrate chat start"
echo "    Then select 'nids_agent'."
