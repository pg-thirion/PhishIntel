import os
import json
from phishintel.intel import IntelPolicy, enrich, triage, summary
from pathlib import Path
import streamlit as st
from phishintel.email import Email, parse_eml, indicators, MAX_TEXT
from phishintel.model import DEMO_PATH, load_data, fit_model, analyse

st.set_page_config(page_title="PhishIntel | Email triage", page_icon="🛡️", layout="wide")
st.title("PhishIntel")
st.caption("EMAIL SECURITY / EXPLAINABLE MACHINE LEARNING")
st.write("Inspect suspicious emails locally. No messages, links or attachments are sent to external services.")
path = Path(os.environ.get("PHISHINTEL_DATA", str(DEMO_PATH)))
demo = path.resolve() == DEMO_PATH.resolve()
if demo:
    st.warning("Demo model: trained on 32 synthetic messages. Scores are illustrative, not validated real-world probabilities.")
else:
    st.info("Custom training dataset configured. Verify its provenance, representativeness and held-out performance.")

@st.cache_resource
def get_model(filename, modified):
    texts, labels, _ = load_data(filename)
    return fit_model(texts, labels), len(labels)

try:
    model, count = get_model(str(path), path.stat().st_mtime_ns)
except (OSError, ValueError) as exc:
    st.error("Could not load training data. Check the configured CSV format and file path.")
    st.stop()

with st.sidebar:
    st.header("Analysis settings")
    threshold = st.slider("Decision threshold", 0.50, 0.99, 0.65, 0.01)
    st.metric("Training messages", count)
    st.caption("Scores are uncalibrated. A low score does not establish safety.")
    st.caption("No live DNS, reputation checks or attachment execution.")
mode = st.radio("Input source", ["Paste email", "Upload .eml"], horizontal=True)
with st.form("analysis"):
    if mode == "Paste email":
        sender = st.text_input("From (optional)", max_chars=500)
        reply = st.text_input("Reply-To (optional)", max_chars=500)
        subject = st.text_input("Subject", max_chars=500)
        body = st.text_area("Email body", height=240, max_chars=MAX_TEXT)
    else:
        uploaded = st.file_uploader("Email file (up to 1 MiB)", type=["eml"])
    submitted = st.form_submit_button("Analyse email", type="primary", use_container_width=True)
if submitted:
    try:
        if mode == "Upload .eml":
            if uploaded is None:
                raise ValueError("Select an email file.")
            email = parse_eml(uploaded.getvalue())
        else:
            email = Email(subject=subject, sender=sender, reply_to=reply, body=body)
        result = analyse(model, email.model_text(), threshold)
    except (ValueError, RecursionError, UnicodeError):
        st.error("Unable to analyse this email. Provide readable text or a valid email under 1 MiB.")
        st.stop()
    st.divider()
    a, b, c = st.columns(3)
    a.metric("Model verdict", result["verdict"])
    b.metric("Phishing model score", f'{result["score"]:.1%}')
    c.metric("Matched features", result["matched_features"])
    st.progress(result["score"])
    st.caption("The model score is based on subject and message text only. Independent indicators below do not alter it.")
    left, right = st.columns(2)
    with left:
        st.subheader("Evidence towards phishing")
        st.dataframe(result["phishing_terms"], hide_index=True, use_container_width=True)
    with right:
        st.subheader("Evidence towards legitimate")
        st.dataframe(result["legitimate_terms"], hide_index=True, use_container_width=True)
    st.caption("Contributions are TF-IDF values multiplied by logistic regression coefficients, in log-odds units.")
    st.subheader("Independent security observations")
    findings = indicators(email)
    try:
        configured = os.environ.get("PHISHINTEL_POLICY")
        policy = IntelPolicy.load(configured) if configured else IntelPolicy()
    except (ValueError, OSError):
        st.error("Invalid configured evidence policy.")
        st.stop()
    evidence = enrich(email, policy)
    decision = triage(result, evidence, findings)
    st.metric("Analyst priority", decision["priority"].title())
    st.caption("Heuristics affect analyst priority, not the ML score.")
    if evidence["findings"]:
        st.dataframe(evidence["findings"], hide_index=True, use_container_width=True)
    with st.expander("Defanged domain inventory"):
        st.text("\n".join(evidence["domains"]))
        st.write(f'{evidence["link_count"]} unique links / {evidence["attachment_count"]} attachments')
    st.download_button("Download metadata-only JSON summary", json.dumps(summary(result, evidence, decision), indent=2), "phishintel-summary.json", "application/json")
    if findings:
        st.dataframe(findings, hide_index=True, use_container_width=True)
    else:
        st.info("No configured indicators triggered. This is not proof of safety.")
    st.subheader("Recommended analyst actions")
    if decision["priority"] != "routine":
        st.write("Do not follow links or open attachments. Verify the request through a known channel and escalate suspicious messages to the security team.")
    else:
        st.write("Verify unexpected requests independently. A low score is not a clearance decision.")
    with st.expander("Technical explanation"):
        st.json({"intercept": result["intercept"], "log_odds": result["log_odds"],
                 "matched_features": result["matched_features"]})
