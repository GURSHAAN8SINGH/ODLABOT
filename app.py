import os
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
import altair as alt

try:
    from dotenv import dotenv_values, load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs): return False
    def dotenv_values(*args, **kwargs): return {}

from odlabot import (
    analyze_log,
    build_follow_up_guidance,
    build_pod_investigation_guidance,
    build_search_guidance,
    build_stakeholder_mail,
    format_analysis_summary,
    format_build_consistency_summary,
    format_build_introduction_summary,
    format_duration_anomaly_summary,
    format_failure_trend_summary,
    format_failing_step_groups_summary,
    format_flaky_test_summary,
    format_jira_group_summary,
    format_node_isolation_summary,
    infer_likely_environment_failure,
    is_build_related_error,
    llm_cluster_explanations,
    llm_enhanced_analysis,
    llm_root_cause_scorecard,
    llm_stakeholder_mail,
    llm_triage_checklist,
    llm_what_happened,
    merge_analysis_inputs,
    read_input_file,
    BUILD_VERSION_FIELDS,
)

ENV_PATH = Path(__file__).with_name(".env")
load_dotenv(dotenv_path=ENV_PATH, override=True)

st.set_page_config(page_title="ODLABOT", layout="wide")
st.title("🤖 ODLABOT — Log Analyzer")
st.caption("Upload .log / .txt / .csv / .xlsx / .xls and get instant triage, charts, and stakeholder summaries.")

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    use_llm = st.checkbox("Enable LLM (OpenRouter)", value=False)
    file_vars = dotenv_values(ENV_PATH) if ENV_PATH.exists() else {}
    default_key = (
        st.session_state.get("openrouter_api_key")
        or os.getenv("OPENROUTER_API_KEY", "").strip()
        or str(file_vars.get("OPENROUTER_API_KEY", "")).strip()
    )
    api_key = st.text_input("OpenRouter API Key", value=default_key, type="password")
    st.session_state["openrouter_api_key"] = api_key
    model = st.text_input("Model", value=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"))
    st.markdown("---")
    st.caption("LLM adds: plain-English summary, triage checklist, root-cause scorecard, cluster explanations, and smarter email drafts.")

# ── Upload ────────────────────────────────────────────────────────────────────
uploaded_file = st.file_uploader(
    "Upload input file",
    type=["log", "txt", "csv", "xlsx", "xls"],
    accept_multiple_files=False,
)

follow_up_evidence = st.text_area(
    "Follow-up evidence (optional)",
    height=140,
    placeholder="Paste kubectl describe, logs, stack traces, or config snippets here to refine diagnosis.",
)

col1, col2 = st.columns(2)
with col1:
    ticket_info = st.text_input("Ongoing ticket info")
    node_history = st.text_area("Previous node/service history", height=90)
with col2:
    verification_results = st.text_area("Verification test results", height=90)
    extra_notes = st.text_area("Additional debugging notes", height=90)

if uploaded_file is None:
    st.info("⬆️ Upload a supported file to start analysis.")
    st.stop()

suffix = "." + uploaded_file.name.split(".")[-1].lower() if "." in uploaded_file.name else ""
with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
    tmp.write(uploaded_file.getvalue())
    temp_path = tmp.name

try:
    lines = read_input_file(temp_path)
except Exception as exc:
    st.error(f"Failed to read uploaded file: {exc}")
    st.stop()

result = analyze_log(lines)
refined_result = analyze_log(merge_analysis_inputs(lines, follow_up_evidence))
ar = refined_result if follow_up_evidence.strip() else result
sev = ar.severity_counts
inference = infer_likely_environment_failure(ar)

# ── Filtering sidebar ─────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("---")
    st.header("🔍 Filter Analysis")
    all_products = [p for p, _ in ar.top_products] if ar.top_products else []
    all_branches = [b for b, _ in ar.top_branches] if ar.top_branches else []
    all_nodes = [n for n, _ in ar.top_nodes] if ar.top_nodes else []
    all_helm = list(ar.build_consistency.version_distributions.get("helm_chart", {}).keys()) if ar.build_consistency else []
    all_helm = [v for v in all_helm if v not in ("", "N/A", "n/a")]

    filter_product = st.multiselect("Product", all_products)
    filter_branch = st.multiselect("Branch", all_branches)
    filter_node = st.multiselect("Node", all_nodes)
    filter_helm = st.multiselect("helm_chart version", all_helm)

def _matches_filters(line: str) -> bool:
    from odlabot import extract_field, normalize_verdict, FAIL_LIKE_VALUES
    if filter_product:
        p = extract_field(line, ["product"])
        if not p or p not in filter_product:
            return False
    if filter_branch:
        b = extract_field(line, ["branch"])
        if not b or b not in filter_branch:
            return False
    if filter_node:
        n = extract_field(line, ["node", "host", "hostname"])
        if not n or n not in filter_node:
            return False
    if filter_helm:
        h = extract_field(line, ["helm_chart"])
        if not h or h not in filter_helm:
            return False
    return True

any_filter = filter_product or filter_branch or filter_node or filter_helm
if any_filter:
    filtered_lines = [l for l in lines if _matches_filters(l)]
    if filtered_lines:
        ar = analyze_log(filtered_lines)
        sev = ar.severity_counts
        inference = infer_likely_environment_failure(ar)
        st.sidebar.success(f"Filter active — {len(filtered_lines)} rows match.")
    else:
        st.sidebar.warning("No rows match the current filters.")

# ── Severity badge helper ─────────────────────────────────────────────────────
def badge(level: str) -> str:
    colors = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵", "OK": "🟢"}
    return colors.get(level, "⚪") + f" **{level}**"

# ── LLM: What Happened ────────────────────────────────────────────────────────
st.markdown("---")
if use_llm and api_key.strip():
    with st.spinner("LLM generating plain-English summary..."):
        try:
            what_happened = llm_what_happened(ar, model=model, api_key=api_key.strip())
            st.info(f"💬 **What happened:** {what_happened}")
        except Exception as exc:
            st.warning(f"LLM summary failed: {exc}")
else:
    top_err = ar.top_error_lines[0][0] if ar.top_error_lines else "unknown errors"
    st.info(
        f"💬 **What happened (heuristic):** {ar.total_lines} rows analyzed in `{ar.data_mode}` mode. "
        f"Dominant issue category is **{inference.reason}** ({inference.confidence} confidence). "
        f"Top recurring failure: `{top_err[:120]}`. "
        f"First failure detected at `{ar.first_failure_timestamp or 'unknown'}`."
    )

# ── Quick Metrics ─────────────────────────────────────────────────────────────
st.subheader("📊 Quick Metrics")
m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Lines", ar.total_lines)
m2.metric("🔴 Fatal", sev["fatal"])
m3.metric("🟠 Error", sev["error"])
m4.metric("🕐 Timeout", sev["timeout"])
m5.metric("🟡 Warning", sev["warning"])
m6.metric("Confidence", inference.confidence.upper())

# ── Charts row 1 ─────────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("📈 Charts")

chart_col1, chart_col2 = st.columns(2)

# Severity pie
with chart_col1:
    sev_df = pd.DataFrame([
        {"Severity": k, "Count": v}
        for k, v in sev.items() if v > 0
    ])
    if not sev_df.empty:
        pie = alt.Chart(sev_df).mark_arc(innerRadius=50).encode(
            theta=alt.Theta("Count:Q"),
            color=alt.Color("Severity:N", scale=alt.Scale(
                domain=["fatal", "error", "timeout", "warning"],
                range=["#d62728", "#ff7f0e", "#9467bd", "#bcbd22"],
            )),
            tooltip=["Severity", "Count"],
        ).properties(title="Severity Distribution", height=260)
        st.altair_chart(pie, use_container_width=True)

# Top failing test cases bar
with chart_col2:
    if ar.top_test_cases:
        tc_df = pd.DataFrame(ar.top_test_cases[:10], columns=["Test Case", "Count"])
        tc_df["Test Case"] = tc_df["Test Case"].str[-50:]
        bar = alt.Chart(tc_df).mark_bar(color="#e45756").encode(
            x=alt.X("Count:Q"),
            y=alt.Y("Test Case:N", sort="-x"),
            tooltip=["Test Case", "Count"],
        ).properties(title="Top Failing Test Cases", height=260)
        st.altair_chart(bar, use_container_width=True)

# Charts row 2
chart_col3, chart_col4 = st.columns(2)

# Failure trend bar chart
with chart_col3:
    if ar.failure_trend and ar.failure_trend.hourly_buckets:
        trend_df = pd.DataFrame(ar.failure_trend.hourly_buckets, columns=["Hour", "Failures"])
        trend_chart = alt.Chart(trend_df).mark_bar(color="#4c78a8").encode(
            x=alt.X("Hour:N", sort=None, axis=alt.Axis(labelAngle=-45)),
            y=alt.Y("Failures:Q"),
            tooltip=["Hour", "Failures"],
        ).properties(title="Hourly Failure Trend", height=260)
        st.altair_chart(trend_chart, use_container_width=True)

# Node failure distribution
with chart_col4:
    if ar.node_isolation and ar.node_isolation.node_failure_counts:
        node_df = pd.DataFrame(
            list(ar.node_isolation.node_failure_counts.items()),
            columns=["Node", "Failures"],
        )
        node_chart = alt.Chart(node_df).mark_bar(color="#f58518").encode(
            x=alt.X("Failures:Q"),
            y=alt.Y("Node:N", sort="-x"),
            tooltip=["Node", "Failures"],
        ).properties(title="Failures by Node", height=260)
        st.altair_chart(node_chart, use_container_width=True)

# Charts row 3
chart_col5, chart_col6 = st.columns(2)

# Duration distribution histogram
with chart_col5:
    if ar.duration_anomalies:
        dur_vals = []
        from odlabot import extract_field
        for line in lines:
            raw = extract_field(line, ["duration"])
            tc = extract_field(line, ["tc_name", "test_case", "testcase"]) or "unknown"
            if raw:
                try:
                    dur_vals.append({"tc_name": tc, "duration": float(raw)})
                except ValueError:
                    pass
        if dur_vals:
            dur_df = pd.DataFrame(dur_vals)
            hist = alt.Chart(dur_df).mark_bar(color="#72b7b2").encode(
                x=alt.X("duration:Q", bin=alt.Bin(maxbins=20), title="Duration (min)"),
                y=alt.Y("count():Q", title="Count"),
                tooltip=["count()"],
            ).properties(title="Duration Distribution", height=260)
            threshold = max(ar.duration_anomalies.median_duration * 3, ar.duration_anomalies.p95_duration)
            rule = alt.Chart(pd.DataFrame({"x": [threshold]})).mark_rule(color="red", strokeDash=[4, 4]).encode(x="x:Q")
            st.altair_chart(hist + rule, use_container_width=True)

# Build version distribution
with chart_col6:
    if ar.build_consistency and ar.build_consistency.version_distributions:
        bv_rows = []
        for component, counter in ar.build_consistency.version_distributions.items():
            for version, count in counter.items():
                if version not in ("", "N/A", "n/a", "na", "none", "null"):
                    bv_rows.append({"Component": component, "Version": version, "Count": count})
        if bv_rows:
            bv_df = pd.DataFrame(bv_rows)
            bv_chart = alt.Chart(bv_df).mark_bar().encode(
                x=alt.X("Count:Q"),
                y=alt.Y("Component:N"),
                color=alt.Color("Version:N"),
                tooltip=["Component", "Version", "Count"],
            ).properties(title="Build Version Distribution", height=260)
            st.altair_chart(bv_chart, use_container_width=True)

def _v_matches(line: str, field: str, version: str) -> bool:
    from odlabot import extract_field
    return extract_field(line, [field]) == version


# ── Side-by-side build comparison ────────────────────────────────────────────
if ar.build_consistency and ar.build_consistency.mismatched:
    st.markdown("---")
    st.subheader("🔀 Side-by-Side Build Comparison")
    comp_field = st.selectbox("Compare by build component", ar.build_consistency.mismatched)
    if comp_field:
        versions = [
            v for v in ar.build_consistency.version_distributions[comp_field]
            if v not in ("", "N/A", "n/a", "na", "none", "null")
        ]
        if len(versions) >= 2:
            comparison_rows = []
            for version in versions:
                filtered = [l for l in lines if _v_matches(l, comp_field, version)]
                v_result = analyze_log(filtered) if filtered else None
                top_tcs = ", ".join(
                    f"{tc[:40]} ({c}x)" for tc, c in (v_result.top_test_cases[:3] if v_result else [])
                ) or "—"
                comparison_rows.append({
                    f"{comp_field} version": version,
                    "Rows": len(filtered),
                    "Failures": sum(v_result.severity_counts.values()) if v_result else 0,
                    "Top failing test cases": top_tcs,
                })
            cmp_df = pd.DataFrame(comparison_rows)
            cmp_df = cmp_df.set_index(f"{comp_field} version")
            st.dataframe(cmp_df, use_container_width=True)

# ── LLM: Root Cause Scorecard ─────────────────────────────────────────────────
st.markdown("---")
st.subheader("🎯 Root Cause Scorecard")
if use_llm and api_key.strip():
    with st.spinner("LLM generating scorecard..."):
        try:
            scorecard = llm_root_cause_scorecard(ar, model=model, api_key=api_key.strip())
            st.markdown(scorecard)
        except Exception as exc:
            st.warning(f"Scorecard failed: {exc}")
else:
    bc = ar.build_consistency
    fi = ar.node_isolation
    fl = ar.flaky_tests
    build_error_confirmed = is_build_related_error(ar)
    # Build issue: same version across all rows AND error text contains build keywords
    build_rating = "HIGH" if (bc and bc.is_build_suspect and build_error_confirmed) else \
                   "MEDIUM" if (bc and bc.is_build_suspect and not build_error_confirmed) else "LOW"
    build_evidence = (
        "Same build across all rows and error text contains build-related keywords (install/deploy/helm/dallas)"
        if bc and bc.is_build_suspect and build_error_confirmed
        else "Same build across all rows but no build-related keywords in error text — may be coincidental"
        if bc and bc.is_build_suspect
        else "Mixed build versions — failures span multiple builds, single build regression unlikely"
    )
    scores = [
        ("Build Issue", build_rating, build_evidence),
        ("Environment / Infra", inference.confidence.upper(),
         f"Dominant failure category: {inference.reason}"),
        ("Flaky Test", "HIGH" if fl and fl.flaky_tests else "LOW",
         f"{len(fl.flaky_tests) if fl else 0} flaky test(s) detected"),
        ("Node Isolation", "HIGH" if fi and fi.is_isolated_to_single_node else "LOW",
         f"All failures on node: {fi.dominant_node}" if fi and fi.is_isolated_to_single_node else "Spread across nodes"),
    ]
    score_df = pd.DataFrame(scores, columns=["Hypothesis", "Rating", "Evidence"])
    st.table(score_df)

# ── LLM: Triage Checklist ─────────────────────────────────────────────────────
st.markdown("---")
st.subheader("✅ Actionable Triage Checklist")
if use_llm and api_key.strip():
    with st.spinner("LLM generating triage checklist..."):
        try:
            checklist = llm_triage_checklist(ar, model=model, api_key=api_key.strip())
            st.markdown(checklist)
        except Exception as exc:
            st.warning(f"Checklist failed: {exc}")
else:
    steps = []
    if ar.node_isolation and ar.node_isolation.is_isolated_to_single_node:
        steps.append(f"Check node `{ar.node_isolation.dominant_node}` health — all failures are isolated here")
    if ar.build_consistency and ar.build_consistency.is_build_suspect:
        steps.append(f"Compare logs before/after build `{ar.build_consistency.consistent[0] if ar.build_consistency.consistent else 'unknown'}` was deployed")
    if ar.flaky_tests and ar.flaky_tests.flaky_tests:
        tc = next(iter(ar.flaky_tests.flaky_tests))
        steps.append(f"Re-run `{tc[:80]}` in isolation — it shows mixed pass/fail behavior")
    if ar.duration_anomalies and ar.duration_anomalies.has_anomalies:
        steps.append(f"Investigate `{ar.duration_anomalies.outliers[0][0][:80]}` — duration outlier detected")
    if ar.jira_groups and ar.jira_groups.untracked_count:
        steps.append(f"Create JIRA tickets for {ar.jira_groups.untracked_count} untracked failure(s)")
    if ar.first_failing_step:
        steps.append(f"Trace root cause from first failing step: `{ar.first_failing_step}`")
    steps.append(f"Focus investigation on `{inference.reason}` — dominant failure pattern")
    steps.append("Re-run targeted verification tests after mitigation and monitor for recurrence")
    for i, s in enumerate(steps[:8], 1):
        st.markdown(f"{i}. {s}")

# ── Technical Summary ─────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("🔬 Technical Summary")
st.code(format_analysis_summary(ar), language="text")

# ── Build Consistency ─────────────────────────────────────────────────────────
if ar.build_consistency:
    st.markdown("---")
    bc = ar.build_consistency
    level = "WARNING" if bc.is_build_suspect else ("INFO" if bc.mismatched else "OK")
    st.subheader(f"{badge(level)} Build Consistency")
    if bc.is_build_suspect:
        st.warning("All build components are on the same version — may be a build-related issue.")
    elif bc.mismatched:
        st.info(f"Builds are mixed across {len(bc.mismatched)} component(s). Single build regression is less likely.")
    else:
        st.success("Build versions are consistent.")
    st.code(format_build_consistency_summary(bc), language="text")

# ── Failure Trend ─────────────────────────────────────────────────────────────
if ar.failure_trend:
    st.markdown("---")
    ft = ar.failure_trend
    level = "WARNING" if ft.is_accelerating else "OK"
    trend_label = "📈 Accelerating" if ft.is_accelerating else "📉 Stable / Declining"
    st.subheader(f"{badge(level)} Failure Trend Over Time")
    c1, c2, c3 = st.columns(3)
    c1.metric("First failure hour", ft.first_failure_hour)
    c2.metric("Peak failure hour", ft.peak_failure_hour)
    c3.metric("Peak count", ft.peak_failure_count)
    st.caption(f"Trend: {trend_label}")
    st.code(format_failure_trend_summary(ft), language="text")

# ── Duration Anomalies ────────────────────────────────────────────────────────
if ar.duration_anomalies:
    st.markdown("---")
    da = ar.duration_anomalies
    level = "WARNING" if da.has_anomalies else "OK"
    st.subheader(f"{badge(level)} Duration Anomalies")
    if da.has_anomalies:
        st.warning(f"{len(da.outliers)} outlier(s) detected — possible hung or stalled runs.")
    else:
        st.success("No duration outliers.")
    st.code(format_duration_anomaly_summary(da), language="text")

# ── Build Introduction ────────────────────────────────────────────────────────
if ar.build_introduction:
    st.markdown("---")
    st.subheader(f"{badge('INFO')} Build Introduction")
    st.info(f"Suspected introducing build: {ar.build_introduction.suspected_build}")
    st.code(format_build_introduction_summary(ar.build_introduction), language="text")

# ── Flaky Tests ───────────────────────────────────────────────────────────────
if ar.flaky_tests:
    st.markdown("---")
    ft2 = ar.flaky_tests
    level = "WARNING" if ft2.flaky_tests else "OK"
    st.subheader(f"{badge(level)} Flaky Test Detection")
    if ft2.flaky_tests:
        st.warning(f"{len(ft2.flaky_tests)} flaky test(s) — these may not be environment failures.")
    st.code(format_flaky_test_summary(ft2), language="text")

# ── JIRA Grouping ─────────────────────────────────────────────────────────────
if ar.jira_groups:
    st.markdown("---")
    jg = ar.jira_groups
    level = "WARNING" if jg.untracked_count else "OK"
    st.subheader(f"{badge(level)} JIRA ID Grouping")
    if jg.untracked_count:
        st.warning(f"{jg.untracked_count} failing row(s) have no JIRA ID.")
    st.code(format_jira_group_summary(jg), language="text")

# ── Node / Cluster Isolation ──────────────────────────────────────────────────
if ar.node_isolation:
    st.markdown("---")
    ni = ar.node_isolation
    level = "CRITICAL" if ni.is_isolated_to_single_node else "WARNING" if ni.is_isolated_to_single_cluster else "INFO"
    st.subheader(f"{badge(level)} Node / Cluster Isolation")
    if ni.is_isolated_to_single_node:
        st.error(f"All failures isolated to node `{ni.dominant_node}` — likely an infra issue.")
    elif ni.is_isolated_to_single_cluster:
        st.warning(f"All failures isolated to cluster `{ni.dominant_cluster}`.")
    else:
        st.info("Failures spread across multiple nodes/clusters.")
    st.code(format_node_isolation_summary(ni), language="text")

# ── Failing Step Groups ───────────────────────────────────────────────────────
if ar.failing_step_groups:
    st.markdown("---")
    st.subheader(f"{badge('INFO')} Failing Step Pattern Groups")
    st.code(format_failing_step_groups_summary(ar.failing_step_groups), language="text")

# ── LLM: Cluster Explanations ────────────────────────────────────────────────
if ar.issue_clusters:
    st.markdown("---")
    st.subheader("🧠 Cluster Explanations")
    if use_llm and api_key.strip():
        with st.spinner("LLM explaining clusters..."):
            try:
                explanations = llm_cluster_explanations(ar, model=model, api_key=api_key.strip())
                st.markdown(explanations)
            except Exception as exc:
                st.warning(f"Cluster explanations failed: {exc}")
    else:
        for i, (scope, category, sig, count) in enumerate(ar.issue_clusters[:6], 1):
            st.markdown(f"{i}. **[{count}x]** `{scope}` — _{category}_ — `{sig[:100]}`")

# ── Runtime Investigation ─────────────────────────────────────────────────────
st.markdown("---")
st.subheader("🔧 Runtime Investigation")
st.code(build_pod_investigation_guidance(ar), language="text")

st.subheader("🔎 Search Guidance")
st.code(build_search_guidance(ar), language="text")

st.subheader("📋 Follow-up Investigation Inputs")
st.code(build_follow_up_guidance(ar), language="text")

# ── Refined Diagnosis ─────────────────────────────────────────────────────────
if follow_up_evidence.strip():
    st.markdown("---")
    st.subheader("🔄 Refined Diagnosis")
    st.caption("Combined upload + follow-up evidence analysis.")
    st.code(format_analysis_summary(refined_result), language="text")
else:
    st.caption("Paste follow-up evidence above to unlock a refined second-stage analysis.")

# ── LLM Triage Analysis ───────────────────────────────────────────────────────
if use_llm and api_key.strip():
    st.markdown("---")
    st.subheader("🤖 LLM Deep Triage Analysis")
    with st.spinner("LLM running deep triage..."):
        try:
            llm_text = llm_enhanced_analysis(result=ar, model=model, api_key=api_key.strip())
            st.markdown(llm_text)
        except Exception as exc:
            st.error(f"OpenRouter analysis failed: {exc}")

# ── Stakeholder Email ─────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("📧 Stakeholder Email Summary")
email_text = ""
if use_llm and api_key.strip():
    with st.spinner("LLM drafting email..."):
        try:
            email_text = llm_stakeholder_mail(
                result=ar, ticket_info=ticket_info, node_history=node_history,
                verification_results=verification_results, extra_notes=extra_notes,
                model=model, api_key=api_key.strip(),
            )
        except Exception as exc:
            st.warning(f"LLM email failed, using heuristic: {exc}")

if not email_text:
    email_text = build_stakeholder_mail(
        result=ar, ticket_info=ticket_info, node_history=node_history,
        verification_results=verification_results, extra_notes=extra_notes,
    )
st.text_area("Email draft", value=email_text, height=320)

# ── Export ────────────────────────────────────────────────────────────────────
st.markdown("---")
report_sections = [
    format_analysis_summary(ar),
    format_build_consistency_summary(ar.build_consistency) if ar.build_consistency else "",
    format_failure_trend_summary(ar.failure_trend) if ar.failure_trend else "",
    format_duration_anomaly_summary(ar.duration_anomalies) if ar.duration_anomalies else "",
    format_build_introduction_summary(ar.build_introduction) if ar.build_introduction else "",
    format_flaky_test_summary(ar.flaky_tests) if ar.flaky_tests else "",
    format_jira_group_summary(ar.jira_groups) if ar.jira_groups else "",
    format_node_isolation_summary(ar.node_isolation) if ar.node_isolation else "",
    format_failing_step_groups_summary(ar.failing_step_groups) if ar.failing_step_groups else "",
    build_pod_investigation_guidance(ar),
    build_search_guidance(ar),
    "--- Stakeholder Email ---",
    email_text,
]
full_report = "\n\n".join(s for s in report_sections if s)
st.download_button(
    label="⬇️ Download full report (.txt)",
    data=full_report,
    file_name="odlabot_report.txt",
    mime="text/plain",
)

try:
    os.unlink(temp_path)
except OSError:
    pass
