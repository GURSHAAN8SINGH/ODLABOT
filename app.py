import os
import tempfile
from pathlib import Path

import streamlit as st
try:
    from dotenv import dotenv_values, load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False
    def dotenv_values(*args, **kwargs):
        return {}

from odlabot import (
    analyze_log,
    build_follow_up_guidance,
    build_pod_investigation_guidance,
    build_search_guidance,
    build_stakeholder_mail,
    format_analysis_summary,
    llm_enhanced_analysis,
    merge_analysis_inputs,
    llm_stakeholder_mail,
    read_input_file,
)

ENV_PATH = Path(__file__).with_name(".env")
load_dotenv(dotenv_path=ENV_PATH, override=True)

st.set_page_config(page_title="ODLABOT", layout="wide")
st.title("ODLABOT - Log Analyzer")
st.caption("Upload .log/.txt/.csv/.xlsx/.xls and generate technical + stakeholder summaries.")

with st.sidebar:
    st.header("LLM Settings")
    use_llm = st.checkbox("Use OpenRouter LLM", value=False)
    file_vars = dotenv_values(ENV_PATH) if ENV_PATH.exists() else {}
    default_key = (
        st.session_state.get("openrouter_api_key")
        or os.getenv("OPENROUTER_API_KEY", "").strip()
        or str(file_vars.get("OPENROUTER_API_KEY", "")).strip()
    )
    api_key = st.text_input("OpenRouter API Key", value=default_key, type="password")
    st.session_state["openrouter_api_key"] = api_key
    model = st.text_input("Model", value=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"))

uploaded_file = st.file_uploader(
    "Upload input file",
    type=["log", "txt", "csv", "xlsx", "xls"],
    accept_multiple_files=False,
)

follow_up_evidence = st.text_area(
    "Follow-up evidence",
    height=180,
    placeholder=(
        "Paste kubectl describe output, kubectl logs, test runner failures, stack traces, "
        "or config snippets here to refine the diagnosis."
    ),
)

col1, col2 = st.columns(2)
with col1:
    ticket_info = st.text_input("Ongoing ticket info")
    node_history = st.text_area("Previous node/service history", height=100)
with col2:
    verification_results = st.text_area("Verification test results", height=100)
    extra_notes = st.text_area("Additional debugging notes", height=100)

if uploaded_file is None:
    st.info("Upload a supported file to start analysis.")
    st.stop()

suffix = "." + uploaded_file.name.split(".")[-1].lower() if "." in uploaded_file.name else ""
with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
    tmp.write(uploaded_file.getvalue())
    temp_path = tmp.name

try:
    lines = read_input_file(temp_path)
except Exception as exc:
    st.error("Failed to read uploaded file: {}".format(exc))
    st.stop()

result = analyze_log(lines)
refined_result = analyze_log(merge_analysis_inputs(lines, follow_up_evidence))
active_result = refined_result if follow_up_evidence.strip() else result
sev = active_result.severity_counts

st.subheader("Quick Metrics")
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Lines", active_result.total_lines)
m2.metric("Fatal", sev["fatal"])
m3.metric("Error", sev["error"])
m4.metric("Timeout", sev["timeout"])
m5.metric("Warning", sev["warning"])

st.subheader("Technical Summary")
if follow_up_evidence.strip():
    st.caption("Primary upload analysis")
    st.code(format_analysis_summary(result), language="text")
else:
    st.code(format_analysis_summary(active_result), language="text")

st.subheader("Runtime Investigation")
st.code(build_pod_investigation_guidance(active_result), language="text")

st.subheader("Search Guidance")
st.code(build_search_guidance(active_result), language="text")

st.subheader("Follow-up Investigation Inputs")
st.code(build_follow_up_guidance(active_result), language="text")

if follow_up_evidence.strip():
    st.subheader("Refined Diagnosis")
    st.caption("This view combines the uploaded file with the follow-up evidence pasted above.")
    st.code(format_analysis_summary(refined_result), language="text")
else:
    st.caption("Paste pod details, extra logs, or test output above to unlock a refined second-stage analysis.")

if use_llm:
    if not api_key.strip():
        st.warning("LLM enabled but API key is missing.")
    else:
        st.subheader("LLM Triage Analysis")
        try:
            llm_text = llm_enhanced_analysis(result=active_result, model=model, api_key=api_key.strip())
            st.write(llm_text)
        except Exception as exc:
            st.error("OpenRouter analysis call failed: {}".format(exc))

st.subheader("Stakeholder Email Summary")
email_text = ""
if use_llm and api_key.strip():
    try:
        email_text = llm_stakeholder_mail(
            result=active_result,
            ticket_info=ticket_info,
            node_history=node_history,
            verification_results=verification_results,
            extra_notes=extra_notes,
            model=model,
            api_key=api_key.strip(),
        )
    except Exception as exc:
        st.warning("OpenRouter email draft failed, using built-in summary: {}".format(exc))

if not email_text:
    email_text = build_stakeholder_mail(
        result=active_result,
        ticket_info=ticket_info,
        node_history=node_history,
        verification_results=verification_results,
        extra_notes=extra_notes,
    )

st.text_area("Email draft", value=email_text, height=320)

try:
    os.unlink(temp_path)
except OSError:
    pass
