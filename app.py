import streamlit as st
import json
import urllib.request
import urllib.parse
import os
from dotenv import load_dotenv
# Load secrets from .env file
load_dotenv()

# --- Configuration ---
st.set_page_config(page_title="NIDS SOC Agent", page_icon="🛡️", layout="wide")
API_KEY = os.getenv("IBM_API_KEY") or os.getenv("WATSONX_API_KEY")
PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "b5711429-279d-45a1-a962-8db58d7bee19")

# --- IBM Watsonx Integration ---
def get_iam_token(api_key: str) -> str:
    iam_url = "https://iam.cloud.ibm.com/identity/token"
    data = urllib.parse.urlencode({"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": api_key}).encode("utf-8")
    req = urllib.request.Request(iam_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]

def ask_ibm_watsonx(user_input: str) -> str:
    token = get_iam_token(API_KEY)
    url = "https://eu-gb.ml.cloud.ibm.com/ml/v1/text/chat?version=2023-05-29"
    
    # This system prompt guarantees the model formats the response exactly as your rubric demands
    system_prompt = """You are an elite Autonomous NIDS SOC Agent powered by IBM watsonx. 
    Analyze the user's security alert prompt and respond with a structured threat mitigation report.
    Format your response clearly using bullet points and markdown. 
    Include:
    1. Attack Categorization (e.g., DoS, Probe, U2R)
    2. Confidence Score / Severity
    3. MITRE ATT&CK ID (if applicable)
    4. Mitigation Recommendation
    5. A valid bash firewall script (e.g., iptables) inside a markdown code block.
    Be concise, authoritative, and directly address the flow IDs or IP addresses mentioned in the prompt."""

    payload = json.dumps({
        "model_id": "meta-llama/llama-3-3-70b-instruct",
        "project_id": PROJECT_ID,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input}
        ],
        "max_tokens": 500,
        "temperature": 0.2
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, method="POST", headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        return body["choices"][0]["message"]["content"].strip()

# --- Streamlit Chat UI ---
st.title("🛡️ Network Intrusion Detection System")
st.markdown("Powered by IBM watsonx.ai · meta-llama/llama-3-3-70b-instruct")

# Initialize memory
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "SOC Agent initialized. Awaiting system alerts or flow logs for analysis."}]

# Draw existing chat
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Accept new prompt
if prompt := st.chat_input("Paste alert log here (e.g., 'Analyze incoming flow ID #8492...'):"):
    # Show user prompt
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
        
    # Generate and show AI response
    with st.chat_message("assistant"):
        with st.spinner("Analyzing threat signatures via IBM watsonx..."):
            try:
                response_text = ask_ibm_watsonx(prompt)
                st.markdown(response_text)
                st.session_state.messages.append({"role": "assistant", "content": response_text})
            except Exception as e:
                st.error(f"Connection Error: {e}")