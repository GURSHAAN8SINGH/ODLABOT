#!/usr/bin/env python3
"""
ODLABOT - Log Analyzer Bot

Features:
- Accepts a log file path
- Analyzes errors/warnings and recurring patterns
- Produces a technical summary
- Suggests practical log search commands
- Asks for additional debugging context
- Generates a stakeholder-ready email summary
"""

from __future__ import annotations

import argparse
import collections
import csv
import dataclasses
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Iterable

try:
    from dotenv import load_dotenv
except ImportError:
    # Allow running without python-dotenv; env vars can still be set in shell.
    def load_dotenv() -> bool:
        return False

SEVERITY_PATTERNS = {
    "fatal": re.compile(r"\b(fatal|panic|critical)\b", re.IGNORECASE),
    "error": re.compile(r"\b(error|exception|failed|failure)\b", re.IGNORECASE),
    "warning": re.compile(r"\b(warn|warning|degraded)\b", re.IGNORECASE),
    "timeout": re.compile(r"\b(timeout|timed out)\b", re.IGNORECASE),
}

TIMESTAMP_PATTERNS = [
    re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:\d{2})?)\b"),
    re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"),
]


@dataclasses.dataclass
class AnalysisResult:
    total_lines: int
    severity_counts: dict[str, int]
    top_error_lines: list[tuple[str, int]]
    top_warning_lines: list[tuple[str, int]]
    issue_clusters: list[tuple[str, str, str, int]]
    sample_timestamps: list[str]
    top_test_cases: list[tuple[str, int]]
    top_products: list[tuple[str, int]]
    top_branches: list[tuple[str, int]]
    top_cluster_ids: list[tuple[str, int]]
    top_fault_ids: list[tuple[str, int]]
    verdict_counts: dict[str, int]
    origins_verdict_counts: dict[str, int]
    data_mode: str
    suspected_components: list[tuple[str, int]]
    top_services: list[tuple[str, int]]
    top_nodes: list[tuple[str, int]]
    top_pods: list[tuple[str, int]]
    first_failure_timestamp: str
    first_failing_step: str
    first_failure_line: str
    repeated_failure_ratio: float


@dataclasses.dataclass
class EnvironmentInference:
    reason: str
    confidence: str
    explanation: str
    evidence: list[str]
    kubernetes_checks: list[str]
    openstack_checks: list[str]


FOLLOW_UP_EVIDENCE_LABELS = (
    "kubectl describe",
    "kubectl logs",
    "kubectl logs --previous",
    "pod events",
    "test runner output",
    "stack trace",
    "config snippet",
)

FAIL_LIKE_VALUES = {"failed", "fail", "failure", "error", "errored", "blocked"}
PASS_LIKE_VALUES = {"passed", "pass", "success", "successful", "ok", "green"}

ISSUE_CATEGORY_PATTERNS = [
    (
        "timeout / connectivity",
        re.compile(
            r"\b(timeout|timed out|connection refused|connection reset|unreachable|dns|"
            r"network|socket|502|503|504|gateway)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "authentication / authorization",
        re.compile(
            r"\b(unauthorized|forbidden|permission denied|auth|token|credential|login)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "configuration / validation",
        re.compile(
            r"\b(invalid|missing|config|configuration|schema|parse|malformed|unsupported|"
            r"not found)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "resource / scheduling",
        re.compile(
            r"\b(oom|out of memory|memory|cpu|disk|pressure|evict|quota|schedule|scheduling)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "crash / runtime",
        re.compile(
            r"\b(panic|fatal|segfault|crash|abort|killed|stack trace|exception)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "dependency / upstream",
        re.compile(
            r"\b(database|db|redis|kafka|queue|broker|upstream|downstream|backend|service unavailable)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "test assertion / regression",
        re.compile(
            r"\b(assertion|expected|actual|mismatch|regression|flaky|test failed|comparison)\b",
            re.IGNORECASE,
        ),
    ),
]


def normalize_line(line: str) -> str:
    out = line.strip()
    out = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:\d{2})?\b", "TIMESTAMP", out)
    out = re.sub(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b", "TIMESTAMP", out)
    out = re.sub(r"\b0x[0-9a-fA-F]+\b", "0xHEX", out)
    out = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b", "UUID", out)
    out = re.sub(r"\b\d+\b", "N", out)
    out = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP", out)
    out = re.sub(r"\s+", " ", out)
    return out[:220]


def detect_component(line: str) -> str | None:
    patterns = [
        re.compile(r"\bservice[=: ]([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"\bmodule[=: ]([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"\bnode[=: ]([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"^\[([A-Za-z0-9._-]+)\]"),
    ]
    for pat in patterns:
        m = pat.search(line)
        if m:
            return m.group(1)
    return None


def extract_field(line: str, names: Iterable[str]) -> str | None:
    stripped = line.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for name in names:
                value = data.get(name)
                if value is not None:
                    value_text = str(value).strip()
                    if value_text:
                        return value_text
    for name in names:
        patterns = [
            re.compile(r"\b%s[=: ]([A-Za-z0-9._/-]+)" % re.escape(name), re.IGNORECASE),
            re.compile(r'"%s"\s*:\s*"([^"]+)"' % re.escape(name), re.IGNORECASE),
        ]
        for pat in patterns:
            match = pat.search(line)
            if match:
                return match.group(1)
    return None


def extract_timestamps(line: str) -> Iterable[str]:
    for pat in TIMESTAMP_PATTERNS:
        m = pat.search(line)
        if m:
            yield m.group(1)


def extract_primary_failure_text(line: str) -> str:
    for field in ["first_error", "first_failing_step", "outline", "message"]:
        value = extract_field(line, [field])
        if value:
            return value
    return line


def classify_issue_category(message: str) -> str:
    for label, pattern in ISSUE_CATEGORY_PATTERNS:
        if pattern.search(message):
            return label
    return "general failure"


def issue_scope_from_line(
    line: str,
    service: str | None = None,
    node: str | None = None,
    pod: str | None = None,
    component: str | None = None,
) -> str:
    parts: list[str] = []
    for part in [service, pod, node, component]:
        if part and part not in parts:
            parts.append(part)
    if parts:
        return " / ".join(parts[:3])
    derived = detect_component(line)
    return derived or "unscoped"


def normalize_verdict(value: str) -> str:
    return re.sub(r"[^a-z]+", "", value.strip().lower())


def infer_data_mode(verdict_counts: dict[str, int], origins_verdict_counts: dict[str, int]) -> str:
    verdict_values = {normalize_verdict(key) for key in verdict_counts}
    origin_values = {normalize_verdict(key) for key in origins_verdict_counts}
    combined = verdict_values | origin_values

    has_fail = any(value in FAIL_LIKE_VALUES for value in combined)
    has_pass = any(value in PASS_LIKE_VALUES for value in combined)

    if has_fail and not has_pass:
        return "failed-only"
    if has_fail and has_pass:
        return "mixed pass/fail"
    if has_pass and not has_fail:
        return "passed-only"
    if verdict_counts or origins_verdict_counts:
        return "verdict-unclassified"
    return "no-verdict-data"


def analyze_log(lines: Iterable[str]) -> AnalysisResult:
    severity_counts = {k: 0 for k in SEVERITY_PATTERNS}
    error_counter: collections.Counter[str] = collections.Counter()
    warning_counter: collections.Counter[str] = collections.Counter()
    issue_cluster_counter: collections.Counter[tuple[str, str, str]] = collections.Counter()
    test_case_counter: collections.Counter[str] = collections.Counter()
    product_counter: collections.Counter[str] = collections.Counter()
    branch_counter: collections.Counter[str] = collections.Counter()
    cluster_id_counter: collections.Counter[str] = collections.Counter()
    fault_id_counter: collections.Counter[str] = collections.Counter()
    verdict_counter: collections.Counter[str] = collections.Counter()
    origins_verdict_counter: collections.Counter[str] = collections.Counter()
    component_counter: collections.Counter[str] = collections.Counter()
    service_counter: collections.Counter[str] = collections.Counter()
    node_counter: collections.Counter[str] = collections.Counter()
    pod_counter: collections.Counter[str] = collections.Counter()
    timestamps: list[str] = []
    total = 0
    first_failure_timestamp = ""
    first_failing_step = ""
    first_failure_line = ""

    for raw in lines:
        total += 1
        line = raw.rstrip("\n")
        lower = line.lower()

        is_error_like = False
        is_warning_like = False

        for sev, pat in SEVERITY_PATTERNS.items():
            if pat.search(lower):
                severity_counts[sev] += 1
                if sev in {"fatal", "error", "timeout"}:
                    is_error_like = True
                if sev == "warning":
                    is_warning_like = True

        primary_failure_text = extract_primary_failure_text(line)

        if is_error_like:
            normalized = normalize_line(primary_failure_text)
            error_counter[normalized] += 1
        elif is_warning_like:
            warning_counter[normalize_line(primary_failure_text)] += 1

        comp = detect_component(line)
        if comp:
            component_counter[comp] += 1

        service = extract_field(line, ["service", "app", "application"])
        product = extract_field(line, ["product"])
        branch = extract_field(line, ["branch"])
        cluster_id = extract_field(line, ["cluster_id"])
        fault_id = extract_field(line, ["fault_id"])
        verdict = extract_field(line, ["verdict"])
        origins_verdict = extract_field(line, ["origins_verdict"])
        test_case = extract_field(line, ["tc_name", "test_case", "testcase"])
        failing_step = extract_field(line, ["first_failing_step"])
        node = extract_field(line, ["node", "host", "hostname"])
        pod = extract_field(line, ["pod", "pod_name", "podname"])
        scope = issue_scope_from_line(
            line,
            service=test_case or service,
            node=None if test_case else node,
            pod=pod,
            component=comp,
        )

        if test_case:
            test_case_counter[test_case] += 1
        if product:
            product_counter[product] += 1
        if branch:
            branch_counter[branch] += 1
        if cluster_id:
            cluster_id_counter[cluster_id] += 1
        if fault_id:
            fault_id_counter[fault_id] += 1
        if verdict:
            verdict_counter[verdict] += 1
        if origins_verdict:
            origins_verdict_counter[origins_verdict] += 1
        if service:
            if is_error_like:
                service_counter[service] += 1
            elif not component_counter[service]:
                component_counter[service] += 1
        if node and is_error_like:
            node_counter[node] += 1
        if pod and is_error_like:
            pod_counter[pod] += 1

        for ts in extract_timestamps(line):
            if len(timestamps) < 30:
                timestamps.append(ts)
            if is_error_like and not first_failure_timestamp:
                first_failure_timestamp = ts
                if failing_step:
                    first_failing_step = failing_step
                first_failure_line = primary_failure_text[:220]

        if is_error_like:
            category = classify_issue_category(primary_failure_text)
            issue_cluster_counter[(scope, category, normalize_line(primary_failure_text))] += 1

    repeated_failures = sum(count for _, count in error_counter.items() if count > 1)
    repeated_failure_ratio = (
        round(repeated_failures / max(sum(error_counter.values()), 1), 3)
        if error_counter
        else 0.0
    )

    return AnalysisResult(
        total_lines=total,
        severity_counts=severity_counts,
        top_error_lines=error_counter.most_common(15),
        top_warning_lines=warning_counter.most_common(8),
        issue_clusters=[
            (scope, category, signature, count)
            for (scope, category, signature), count in issue_cluster_counter.most_common(12)
        ],
        sample_timestamps=timestamps[:10],
        top_test_cases=test_case_counter.most_common(8),
        top_products=product_counter.most_common(8),
        top_branches=branch_counter.most_common(8),
        top_cluster_ids=cluster_id_counter.most_common(8),
        top_fault_ids=fault_id_counter.most_common(8),
        verdict_counts=dict(verdict_counter),
        origins_verdict_counts=dict(origins_verdict_counter),
        data_mode=infer_data_mode(dict(verdict_counter), dict(origins_verdict_counter)),
        suspected_components=component_counter.most_common(8),
        top_services=service_counter.most_common(8),
        top_nodes=node_counter.most_common(8),
        top_pods=pod_counter.most_common(8),
        first_failure_timestamp=first_failure_timestamp,
        first_failing_step=first_failing_step,
        first_failure_line=first_failure_line,
        repeated_failure_ratio=repeated_failure_ratio,
    )


def split_follow_up_evidence(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line:
            lines.append(line)
    return lines


def merge_analysis_inputs(primary_lines: Iterable[str], follow_up_text: str) -> list[str]:
    merged = list(primary_lines)
    follow_up_lines = split_follow_up_evidence(follow_up_text)
    if follow_up_lines:
        merged.append("FOLLOW_UP_EVIDENCE_BEGIN")
        merged.extend(follow_up_lines)
        merged.append("FOLLOW_UP_EVIDENCE_END")
    return merged


def prompt_text(label: str, optional: bool = True) -> str:
    suffix = " (optional)" if optional else ""
    try:
        return input(f"{label}{suffix}: ").strip()
    except EOFError:
        return ""


def yes_no(question: str) -> bool:
    while True:
        try:
            value = input(f"{question} [y/n]: ").strip().lower()
        except EOFError:
            return False
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please answer y or n.")


def build_search_guidance(result: AnalysisResult) -> str:
    hot_terms = []
    for msg, _ in result.top_error_lines[:3]:
        hot_terms.extend(extract_hot_terms(msg, limit=3))
    unique_terms = list(dict.fromkeys(hot_terms))[:8]
    term_string = " ".join(unique_terms) if unique_terms else "error exception timeout failed"

    primary_service = (
        result.top_test_cases[0][0]
        if result.top_test_cases
        else result.top_services[0][0]
        if result.top_services
        else "<service>"
    )
    primary_node = result.top_nodes[0][0] if result.top_nodes else "<node>"
    primary_pod = result.top_pods[0][0] if result.top_pods else "<pod>"
    first_failure_ts = result.first_failure_timestamp or "<timestamp>"

    exact_signature = (
        result.top_error_lines[0][0]
        if result.top_error_lines
        else "error|exception|fatal|timeout|failed"
    )
    warning_terms = []
    for msg, _ in result.top_warning_lines[:2]:
        warning_terms.extend(extract_hot_terms(msg, limit=2))
    warning_string = " ".join(list(dict.fromkeys(warning_terms))[:4]) or "warning retry slow degraded"

    guidance = [
        "Search strategy:",
        f"1) Start broad and quantify failure lines: rg -n -i \"error|exception|fatal|timeout|failed\" <logfile>",
        f"2) Pivot to the dominant failure text: rg -n -i \"{term_string}\" <logfile>",
        f"3) Lock onto the affected workload: rg -n -i \"{primary_service}|{primary_node}|{primary_pod}\" <logfile>",
        f"4) Look at the first failure window around {first_failure_ts} and the next 2-5 minutes for causality",
        f"5) Compare early warnings to failures: rg -n -i \"{warning_string}\" <logfile>",
        f"6) Confirm the exact recurring signature count: rg -n -F \"{exact_signature}\" <logfile>",
        "7) If logs are huge, start with tail or a sliced export around the first failure before widening the search",
    ]
    if result.issue_clusters:
        guidance.append("8) Issue-specific follow-up searches:")
        for idx, (scope, category, signature, count) in enumerate(result.issue_clusters[:4], start=1):
            issue_pattern = build_issue_search_pattern(scope, signature)
            guidance.append(f"   {idx}. {scope} [{category}, {count} hits]")
            guidance.append(f"      rg -n -i \"{issue_pattern}\" <logfile>")
            for hint in build_issue_remediation_hint(category, scope)[:2]:
                guidance.append(f"      {hint}")
    return "\n".join(guidance)


def build_test_run_investigation_guidance(result: AnalysisResult) -> str:
    tc_name = result.top_test_cases[0][0] if result.top_test_cases else "<test_case>"
    first_step = result.first_failing_step or "<first_failing_step>"
    first_error = result.top_error_lines[0][0] if result.top_error_lines else "<first_error>"
    product = result.top_products[0][0] if result.top_products else "<product>"
    branch = result.top_branches[0][0] if result.top_branches else "<branch>"
    first_error_terms = extract_hot_terms(first_error, limit=4)
    first_error_term = first_error_terms[0] if first_error_terms else first_error
    inference = infer_likely_environment_failure(result)

    commands = [
        "Test run investigation checklist:",
        f"Data mode: {result.data_mode}",
        f"This likely points to a {inference.reason} issue ({inference.confidence} confidence).",
        "1) Find all runs of the same test case:",
        f"   rg -n -i \"{tc_name}\" <csv-or-excel-export>",
        "2) Compare the main error text across runs:",
        f"   rg -n -i \"{first_error_term}\" <csv-or-excel-export>",
        "3) Check whether the same step fails each time:",
        f"   rg -n -i \"{first_step}\" <csv-or-excel-export>",
        "4) Split by product and branch to see whether it is environment-specific:",
        f"   rg -n -i \"{product}|{branch}\" <csv-or-excel-export>",
        "5) If you have a fault or JIRA id, use it to group related regressions:",
        "   rg -n -i \"fault_id|jira_id\" <csv-or-excel-export>",
    ]
    if result.issue_clusters:
        commands.append("6) Separate issue groups found in the export:")
        for scope, category, signature, count in result.issue_clusters[:4]:
            commands.append(f"   - {scope} [{category}, {count} rows]")
            commands.append(f"     first_error: {signature}")
    commands.append("")
    commands.append(build_k8s_openstack_checks(result))
    return "\n".join(commands)


def extract_hot_terms(message: str, limit: int = 4) -> list[str]:
    focus_text = message
    if "message=" in message:
        focus_text = message.split("message=", 1)[1]
    elif " ERROR " in message:
        focus_text = message.split(" ERROR ", 1)[1]
    elif " WARNING " in message:
        focus_text = message.split(" WARNING ", 1)[1]

    words = [w for w in re.split(r"[^A-Za-z0-9._/-]+", focus_text) if len(w) > 4]
    stopwords = {
        "timestamp",
        "service",
        "module",
        "level",
        "message",
        "warning",
        "error",
        "failed",
        "failure",
        "exception",
        "while",
        "calling",
        "during",
        "request",
        "response",
        "received",
        "observed",
        "detected",
        "details",
        "status",
        "event",
        "events",
        "erroring",
        "errorcode",
    }
    filtered = [
        word for word in words
        if word.lower() not in stopwords
    ]
    return list(dict.fromkeys(filtered))[:limit]


def build_issue_search_pattern(scope: str, signature: str) -> str:
    terms = extract_hot_terms(signature, limit=4)
    terms.extend(extract_hot_terms(scope, limit=3))
    unique_terms = list(dict.fromkeys(term for term in terms if term))
    if not unique_terms:
        return "error exception timeout failed"
    return "|".join(re.escape(term) for term in unique_terms[:6])


def build_issue_remediation_hint(category: str, scope: str) -> list[str]:
    base = [
        f"- Focus this pass on `{scope}` and confirm whether the same signature repeats across related logs.",
    ]
    if category == "timeout / connectivity":
        base.extend(
            [
                "- Check DNS, ingress, service discovery, and upstream latency before treating it as an app bug.",
                "- Compare this failure window with network or dependency outages.",
            ]
        )
    elif category == "authentication / authorization":
        base.extend(
            [
                "- Verify service account, token, secret rotation, and permission changes.",
                "- Check whether the failure started right after an auth policy or secret update.",
            ]
        )
    elif category == "configuration / validation":
        base.extend(
            [
                "- Diff the live config against the last known good deployment.",
                "- Inspect schema, environment variable, and manifest validation errors.",
            ]
        )
    elif category == "resource / scheduling":
        base.extend(
            [
                "- Inspect pod restarts, OOM kills, CPU throttling, node pressure, and eviction events.",
                "- Check whether resource requests/limits changed recently.",
            ]
        )
    elif category == "crash / runtime":
        base.extend(
            [
                "- Pull the previous container logs and stack trace around the first crash.",
                "- Confirm whether the crash is deterministic or tied to a specific input path.",
            ]
        )
    elif category == "dependency / upstream":
        base.extend(
            [
                "- Check the upstream system status and any recent dependency contract changes.",
                "- Compare retry behavior and circuit-breaker behavior across runs.",
            ]
        )
    elif category == "test assertion / regression":
        base.extend(
            [
                "- Compare expected vs actual output, fixture changes, and test data drift.",
                "- Re-run the exact test channel in isolation to confirm whether the issue is reproducible.",
            ]
        )
    else:
        base.extend(
            [
                "- Keep digging until the log evidence points to a concrete subsystem instead of a generic error bucket.",
                "- If multiple clusters exist, investigate them independently rather than using one shared command.",
            ]
        )
    return base


def normalize_scope_case(scope: str) -> str:
    return scope.split(" / ", 1)[0].strip()


def summarize_issue_categories(result: AnalysisResult) -> collections.Counter[str]:
    totals: collections.Counter[str] = collections.Counter()
    for _, category, _, count in result.issue_clusters:
        totals[category] += count
    return totals


def infer_likely_environment_failure(result: AnalysisResult) -> EnvironmentInference:
    category_totals = summarize_issue_categories(result)
    dominant_category = category_totals.most_common(1)[0][0] if category_totals else "general failure"
    dominant_category_count = category_totals[dominant_category] if category_totals else 0
    total_cluster_hits = sum(category_totals.values()) or 1
    cluster_support = dominant_category_count / total_cluster_hits
    unique_cases = len({normalize_scope_case(scope) for scope, _, _, _ in result.issue_clusters})
    repeated_signature_count = result.top_error_lines[0][1] if result.top_error_lines else 0
    total_errors = sum(result.severity_counts.values()) or 1
    repeated_ratio = repeated_signature_count / total_errors

    if dominant_category == "configuration / validation":
        reason = "configuration rollout or environment drift"
        kubernetes_checks = [
            "kubectl get deploy,sts,cm,secret -A",
            "kubectl describe deploy <deployment> -n <namespace>",
            "kubectl rollout status deploy/<deployment> -n <namespace>",
            "kubectl diff -f <manifest-dir>",
            "kubectl get events -A --sort-by=.lastTimestamp | tail -n 50",
        ]
        openstack_checks = [
            "openstack server show <server>",
            "openstack console log show <server> | tail -n 200",
            "openstack stack list",
            "openstack stack show <stack>",
        ]
    elif dominant_category == "timeout / connectivity":
        reason = "network or service-discovery instability"
        kubernetes_checks = [
            "kubectl get svc,endpoints,ep -A",
            "kubectl get netpol -A",
            "kubectl describe pod <pod>",
            "kubectl get events -A --sort-by=.lastTimestamp | tail -n 50",
        ]
        openstack_checks = [
            "openstack network agent list",
            "openstack port list --server <server>",
            "openstack router list",
            "openstack subnet list",
        ]
    elif dominant_category == "resource / scheduling":
        reason = "node pressure, quota, or scheduling shortage"
        kubernetes_checks = [
            "kubectl describe node <node>",
            "kubectl top nodes",
            "kubectl top pods -A --sort-by=memory",
            "kubectl get pod -A -o wide | rg -i \"Evicted|CrashLoopBackOff|OOMKilled\"",
        ]
        openstack_checks = [
            "openstack hypervisor list",
            "openstack hypervisor stats show",
            "openstack hypervisor show <hypervisor>",
            "openstack quota show <project>",
        ]
    elif dominant_category == "authentication / authorization":
        reason = "RBAC, secret, or identity change"
        kubernetes_checks = [
            "kubectl get sa,role,rolebinding,secret -A",
            "kubectl describe sa <serviceaccount> -n <namespace>",
            "kubectl describe secret <secret> -n <namespace>",
            "kubectl get events -A --sort-by=.lastTimestamp | tail -n 50",
        ]
        openstack_checks = [
            "openstack token issue",
            "openstack user list",
            "openstack role assignment list --user <user>",
            "openstack project list",
        ]
    elif dominant_category == "dependency / upstream":
        reason = "upstream dependency outage or contract mismatch"
        kubernetes_checks = [
            "kubectl get deploy -A | rg -i \"db|redis|mq|broker|backend|upstream\"",
            "kubectl get svc,endpoints,ep -A",
            "kubectl describe pod <pod>",
            "kubectl get events -A --sort-by=.lastTimestamp | tail -n 50",
        ]
        openstack_checks = [
            "openstack server list --long",
            "openstack server show <server>",
            "openstack compute service list",
            "openstack hypervisor list",
        ]
    elif dominant_category == "crash / runtime":
        reason = "application crash or bad runtime build"
        kubernetes_checks = [
            "kubectl get pods -A -o wide",
            "kubectl describe pod <pod>",
            "kubectl get events -A --sort-by=.lastTimestamp | tail -n 50",
            "kubectl get pod -A -o wide | rg -i \"CrashLoopBackOff|OOMKilled|Error\"",
        ]
        openstack_checks = [
            "openstack server show <server>",
            "openstack console log show <server> | tail -n 200",
            "openstack compute service list",
            "openstack hypervisor list",
        ]
    elif dominant_category == "test assertion / regression":
        reason = "test data drift or product regression"
        kubernetes_checks = [
            "kubectl get pods -A -o wide",
            "kubectl get events -A --sort-by=.lastTimestamp | tail -n 50",
            "kubectl describe pod <pod>",
            "kubectl rollout status deploy/<deployment> -n <namespace>",
        ]
        openstack_checks = [
            "openstack server list --long",
            "openstack server show <server>",
            "openstack console log show <server> | tail -n 200",
            "openstack stack list",
        ]
    else:
        reason = "mixed environment failures"
        kubernetes_checks = [
            "kubectl get pods -A -o wide",
            "kubectl get nodes -o wide",
            "kubectl get events -A --sort-by=.lastTimestamp | tail -n 50",
            "kubectl describe pod <pod>",
        ]
        openstack_checks = [
            "openstack server list --long",
            "openstack server show <server>",
            "openstack compute service list",
            "openstack hypervisor list",
        ]

    confidence_score = 0
    if cluster_support >= 0.6:
        confidence_score += 2
    elif cluster_support >= 0.35:
        confidence_score += 1
    if unique_cases >= 3:
        confidence_score += 2
    elif unique_cases >= 2:
        confidence_score += 1
    if repeated_ratio >= 0.35:
        confidence_score += 1
    if len(result.issue_clusters) >= 3:
        confidence_score += 1

    if confidence_score >= 5:
        confidence = "high"
    elif confidence_score >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    explanation = (
        f"Dominant category is `{dominant_category}` with {dominant_category_count} clustered hits "
        f"across {unique_cases} test-case groups; the leading signature repeats in {repeated_ratio:.0%} "
        f"of the matched failure lines."
    )
    if dominant_category == "configuration / validation" and unique_cases >= 2:
        explanation += " This pattern is consistent with a shared environment/configuration failure rather than a single testcase defect."
    elif dominant_category == "resource / scheduling" and unique_cases >= 2:
        explanation += " The spread across test cases suggests an infrastructure capacity or scheduling issue."
    elif dominant_category == "timeout / connectivity" and unique_cases >= 2:
        explanation += " Multiple affected cases point toward a common network or service-discovery problem."

    evidence = [
        f"Dominant category: {dominant_category}",
        f"Clustered hits: {dominant_category_count}",
        f"Unique test-case groups affected: {unique_cases}",
        f"Repeated signature ratio: {repeated_ratio:.0%}",
    ]

    return EnvironmentInference(
        reason=reason,
        confidence=confidence,
        explanation=explanation,
        evidence=evidence,
        kubernetes_checks=kubernetes_checks,
        openstack_checks=openstack_checks,
    )


def build_cluster_focus(result: AnalysisResult) -> str:
    parts = []
    if result.top_test_cases:
        parts.append(result.top_test_cases[0][0])
    if result.top_nodes:
        parts.append(result.top_nodes[0][0])
    if result.top_cluster_ids and not result.top_cluster_ids[0][0].isdigit():
        parts.append(result.top_cluster_ids[0][0])
    if result.top_products:
        parts.append(result.top_products[0][0])
    if not parts:
        return "<cluster>"
    return " / ".join(parts[:3])


def has_issue_category(result: AnalysisResult, needle: str) -> bool:
    return any(needle == category for _, category, _, _ in result.issue_clusters)


def build_k8s_openstack_checks(result: AnalysisResult) -> str:
    focus = build_cluster_focus(result)
    test_case = result.top_test_cases[0][0] if result.top_test_cases else "<test_case>"
    target_node = result.top_nodes[0][0] if result.top_nodes else "<node>"
    product = result.top_products[0][0] if result.top_products else "<product>"
    branch = result.top_branches[0][0] if result.top_branches else "<branch>"
    cluster_id = (
        result.top_cluster_ids[0][0]
        if result.top_cluster_ids and not result.top_cluster_ids[0][0].isdigit()
        else None
    )
    openstack_focus_terms = [target_node, test_case, product, branch]
    if cluster_id:
        openstack_focus_terms.append(cluster_id)
    openstack_focus = "|".join(openstack_focus_terms)

    inference = infer_likely_environment_failure(result)

    lines = [
        f"Runtime checks for `{focus}`:",
        "Note: testcase logs are not expected in pods or cluster logs, so use infra state, rollout, and console evidence instead of `kubectl logs`.",
        f"Dataset mode: {result.data_mode}",
        f"Likely environment failure reason: {inference.reason}",
        f"Confidence: {inference.confidence}",
        f"Why: {inference.explanation}",
        "Evidence:",
    ]
    for item in inference.evidence:
        lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "Kubernetes checks:",
        ]
    )
    for idx, cmd in enumerate(inference.kubernetes_checks, start=1):
        lines.append(f"{idx}) {cmd}")

    lines.extend(
        [
            "",
            "OpenStack checks:",
        ]
    )
    for idx, cmd in enumerate(inference.openstack_checks, start=1):
        lines.append(f"{idx}) {cmd}")

    lines.extend(
        [
            "",
            "Additional correlation:",
            f"   openstack server list --long | rg -i \"{openstack_focus}\"",
        ]
    )

    if result.top_fault_ids and not result.top_fault_ids[0][0].isdigit():
        lines.append(
            f"   openstack server show <server>  # compare server fault/status details with IDs like {result.top_fault_ids[0][0]}"
        )

    lines.extend(
        [
            "",
            "Use the command pack that matches the inferred environment failure, then compare the same test case across failed and passing channels.",
        ]
    )
    return "\n".join(lines)


def build_pod_investigation_guidance(result: AnalysisResult) -> str:
    if result.top_test_cases:
        return build_test_run_investigation_guidance(result)

    service = result.top_services[0][0] if result.top_services else "<service>"
    pod = result.top_pods[0][0] if result.top_pods else "<pod>"
    node = result.top_nodes[0][0] if result.top_nodes else "<node>"
    signature = result.top_error_lines[0][0] if result.top_error_lines else "error exception timeout failed"
    search_terms = " ".join(extract_hot_terms(signature)) or "error exception timeout failed"

    commands = [
        "Pod investigation guidance:",
        "1) Find the failing pod quickly:",
        f"   kubectl get pods -A | rg \"{service}|{pod}|{node}\"",
        "2) Review recent pod logs with context:",
        f"   kubectl logs {pod} --tail=200 | rg -n \"{search_terms}\"",
        "3) Check previous container logs after crash/restart:",
        f"   kubectl logs {pod} --previous --tail=200",
        "4) Inspect pod events, restarts, and scheduling issues:",
        f"   kubectl describe pod {pod}",
        "5) Exec into the pod for config/process checks when needed:",
        f"   kubectl exec -it {pod} -- /bin/sh",
    ]
    if result.issue_clusters:
        commands.append("6) Issue-specific focus:")
        for scope, category, signature, count in result.issue_clusters[:3]:
            commands.append(f"   - {scope} [{category}, {count} hits]")
            for hint in build_issue_remediation_hint(category, scope)[:2]:
                commands.append(f"     {hint}")
    return "\n".join(commands)


def build_follow_up_guidance(result: AnalysisResult) -> str:
    if result.top_test_cases:
        tc_name = result.top_test_cases[0][0] if result.top_test_cases else "<test_case>"
        first_step = result.first_failing_step or "<first_failing_step>"
        first_error = result.top_error_lines[0][0] if result.top_error_lines else "<first_error>"
        inference = infer_likely_environment_failure(result)
        return "\n".join(
            [
                "Follow-up evidence to paste for deeper analysis:",
                f"Likely environment failure reason: {inference.reason} ({inference.confidence} confidence)",
                f"1) The failing `{tc_name}` row or a small slice of rows around it",
                f"2) The exact `first_failing_step` text: {first_step}",
                f"3) The full `first_error` text: {first_error}",
                "4) Any additional rows from the same branch/product that fail for a different reason",
                "5) Notes on whether the failure is isolated to one channel, one cluster, or one branch",
            ]
        )

    service = result.top_services[0][0] if result.top_services else "<service>"
    node = result.top_nodes[0][0] if result.top_nodes else "<node>"
    pod = result.top_pods[0][0] if result.top_pods else "<pod>"
    timestamp = result.first_failure_timestamp or "<timestamp>"

    steps = [
        "Follow-up evidence to paste for deeper analysis:",
        f"1) `kubectl describe pod {pod}` to capture restart, readiness, and event details",
        f"2) `kubectl logs {pod} --since=10m` around {timestamp} for the live failure stream",
        f"3) `kubectl logs {pod} --previous --tail=200` if the container restarted",
        f"4) Test runner output or assertion summary for the failing `{service}` workload",
        f"5) Any node-specific details for `{node}` such as resource pressure, mount, DNS, or network symptoms",
    ]
    return "\n".join(steps)


def format_analysis_summary(result: AnalysisResult) -> str:
    sev = result.severity_counts
    inference = infer_likely_environment_failure(result)
    category_totals = summarize_issue_categories(result)
    dominant_category = category_totals.most_common(1)[0][0] if category_totals else "general failure"
    dominant_category_hits = category_totals[dominant_category] if category_totals else 0
    top_case = result.top_test_cases[0][0] if result.top_test_cases else "Not identified"
    top_product = result.top_products[0][0] if result.top_products else "Not identified"
    top_branch = result.top_branches[0][0] if result.top_branches else "Not identified"
    top_cluster = result.top_cluster_ids[0][0] if result.top_cluster_ids else "Not identified"
    top_fault = result.top_fault_ids[0][0] if result.top_fault_ids else "Not identified"
    verdicts = ", ".join([f"{name}={count}" for name, count in sorted(result.verdict_counts.items())]) or "Not available"
    origin_verdicts = ", ".join([f"{name}={count}" for name, count in sorted(result.origins_verdict_counts.items())]) or "Not available"

    def format_top_items(items: list[tuple[str, int]], limit: int = 5) -> str:
        return ", ".join([f"{name}({count})" for name, count in items[:limit]])

    lines = [
        "Technical summary:",
        f"- Total log lines analyzed: {result.total_lines}",
        f"- Data mode: {result.data_mode}",
        f"- Verdict counts: {verdicts}",
        f"- Origin verdict counts: {origin_verdicts}",
        (
            "- Severity indicators found: "
            f"fatal={sev['fatal']}, error={sev['error']}, timeout={sev['timeout']}, warning={sev['warning']}"
        ),
        f"- Dominant issue category: {dominant_category} ({dominant_category_hits} clustered hits)",
        f"- Likely root cause: {inference.reason} ({inference.confidence} confidence)",
        f"- Short explanation: {inference.explanation}",
    ]
    if result.data_mode == "failed-only":
        lines.append("- Dataset note: failed-only mode, so the summary is focused on repeated failure patterns.")
    elif result.data_mode == "mixed pass/fail":
        lines.append("- Dataset note: mixed pass/fail data, so failed rows can be compared against passing rows.")
    elif result.data_mode == "passed-only":
        lines.append("- Dataset note: passed-only data, so failure clustering is limited.")
    if result.first_failure_timestamp:
        lines.append(f"- First detected failure timestamp: {result.first_failure_timestamp}")
    if result.first_failing_step:
        lines.append(f"- First failing step: {result.first_failing_step}")
    if result.first_failure_line:
        lines.append(f"- First failure signature: {result.first_failure_line}")
    lines.append(f"- Top failing test case: {top_case}")
    if result.top_services:
        lines.append(f"- Services with most failures: {format_top_items(result.top_services)}")
    if result.top_nodes:
        lines.append(f"- Nodes with most failures: {format_top_items(result.top_nodes)}")
    if result.top_pods:
        lines.append(f"- Pods with most failures: {format_top_items(result.top_pods)}")
    if result.top_error_lines:
        dominant_failures = sum(count for _, count in result.top_error_lines[:5])
        lines.append(
            f"- Repeated failure concentration: {result.repeated_failure_ratio:.1%} of failure lines belong to recurring signatures"
        )
        lines.append(f"- Dominant top-5 failure signatures account for {dominant_failures} matched failure lines")
    if result.top_products:
        lines.append(f"- Product focus: {format_top_items(result.top_products)}")
    if result.top_branches:
        lines.append(f"- Branch focus: {format_top_items(result.top_branches)}")
    if result.top_cluster_ids:
        lines.append(f"- Cluster IDs: {format_top_items(result.top_cluster_ids)}")
    if result.top_fault_ids:
        lines.append(f"- Fault IDs: {format_top_items(result.top_fault_ids)}")
    if result.issue_clusters:
        lines.append("- Distinct issue clusters identified:")
        for scope, category, signature, count in result.issue_clusters[:5]:
            lines.append(f"  - [{count}x] {scope} | {category} | {signature}")
    if result.sample_timestamps:
        lines.append(f"- Sample timeline markers: {', '.join(result.sample_timestamps[:5])}")
    if result.top_test_cases:
        lines.append(f"- Test cases with most rows: {format_top_items(result.top_test_cases)}")
    if result.suspected_components:
        lines.append(f"- Most referenced components/nodes: {format_top_items(result.suspected_components)}")
    if result.top_error_lines:
        lines.append("- Top recurring failure signatures:")
        for msg, count in result.top_error_lines[:8]:
            lines.append(f"  - [{count}x] {msg}")
    if result.top_warning_lines:
        lines.append("- Top recurring warning signatures:")
        for msg, count in result.top_warning_lines[:3]:
            lines.append(f"  - [{count}x] {msg}")
    return "\n".join(lines)


def build_stakeholder_mail(
    result: AnalysisResult,
    ticket_info: str,
    node_history: str,
    verification_results: str,
    extra_notes: str,
) -> str:
    sev = result.severity_counts
    inference = infer_likely_environment_failure(result)
    top_issue = result.top_error_lines[0][0] if result.top_error_lines else "No dominant error signature identified"
    component_hint = (
        result.top_test_cases[0][0]
        if result.top_test_cases
        else result.suspected_components[0][0]
        if result.suspected_components
        else "component pending confirmation"
    )
    issue_overview = (
        ", ".join([f"{scope} [{category}]" for scope, category, _, _ in result.issue_clusters[:3]])
        if result.issue_clusters
        else "No distinct issue clusters identified"
    )

    mail = [
        "Subject: Incident Update - Log Analysis Summary",
        "",
        "Hello Stakeholders,",
        "",
        "Please find the latest analysis update below:",
        "",
        "1. What we observed",
        f"- Total lines reviewed: {result.total_lines}",
        f"- Data mode: {result.data_mode}",
        f"- Error indicators: fatal={sev['fatal']}, error={sev['error']}, timeout={sev['timeout']}, warning={sev['warning']}",
        f"- Top failing test case: {result.top_test_cases[0][0] if result.top_test_cases else 'Not identified'}",
        f"- Primary recurring issue: {top_issue}",
        f"- Likely environment failure reason: {inference.reason} ({inference.confidence} confidence)",
        f"- Distinct issue clusters: {issue_overview}",
        f"- Most likely affected area: {component_hint}",
        f"- Product / branch focus: {result.top_products[0][0] if result.top_products else 'Not identified'} / {result.top_branches[0][0] if result.top_branches else 'Not identified'}",
        "",
        "2. Current context",
        f"- Ongoing ticket details: {ticket_info or 'Not provided'}",
        f"- Node/service history: {node_history or 'Not provided'}",
        f"- Verification test results: {verification_results or 'Not provided'}",
        f"- Additional notes: {extra_notes or 'None'}",
        "",
        "3. Next debugging actions",
        "- Confirm first failure timestamp and validate preceding warnings",
        "- Compare affected node/component with recent config or deployment changes",
        "- Re-run targeted verification tests after mitigation and monitor recurrence",
        "",
        "Regards,",
        "ODLABOT",
    ]
    return "\n".join(mail)


def call_openrouter(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    timeout: int = 45,
) -> str:
    url = "https://openrouter.ai/api/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost/odlabot",
            "X-Title": "ODLABOT",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
    parsed = json.loads(raw)
    choices = parsed.get("choices") or []
    if not choices:
        raise RuntimeError("OpenRouter returned no choices.")
    message = choices[0].get("message", {})
    content = message.get("content", "")
    if not content:
        raise RuntimeError("OpenRouter returned empty content.")
    return content.strip()


def llm_enhanced_analysis(result: AnalysisResult, model: str, api_key: str) -> str:
    inference = infer_likely_environment_failure(result)
    system = (
        "You are a senior production support engineer. "
        "Prioritize root-cause analysis, triage guidance, and pod-level debugging steps over stakeholder messaging."
    )
    user = (
        "Create a compact analysis with sections: "
        "Likely Cause, Failure Pattern, Pod Checks, Next Checks, Fast Search Queries.\n\n"
        f"Total lines: {result.total_lines}\n"
        f"Data mode: {result.data_mode}\n"
        f"Severity: {result.severity_counts}\n"
        f"First failure timestamp: {result.first_failure_timestamp or 'unknown'}\n"
        f"First failing step: {result.first_failing_step or 'unknown'}\n"
        f"First failure line: {result.first_failure_line or 'unknown'}\n"
        f"Likely environment failure reason: {inference.reason} ({inference.confidence} confidence)\n"
        f"Why: {inference.explanation}\n"
        f"Top errors: {result.top_error_lines[:5]}\n"
        f"Top warnings: {result.top_warning_lines[:5]}\n"
        f"Issue clusters: {result.issue_clusters[:5]}\n"
        f"Test cases: {result.top_test_cases[:5]}\n"
        f"Products: {result.top_products[:5]}\n"
        f"Branches: {result.top_branches[:5]}\n"
        f"Components: {result.suspected_components[:5]}\n"
        f"Services: {result.top_services[:5]}\n"
        f"Nodes: {result.top_nodes[:5]}\n"
        f"Pods: {result.top_pods[:5]}\n"
        f"Timestamps: {result.sample_timestamps[:6]}\n"
    )
    return call_openrouter(api_key=api_key, model=model, system_prompt=system, user_prompt=user)


def llm_stakeholder_mail(
    result: AnalysisResult,
    ticket_info: str,
    node_history: str,
    verification_results: str,
    extra_notes: str,
    model: str,
    api_key: str,
) -> str:
    inference = infer_likely_environment_failure(result)
    system = (
        "You write stakeholder incident updates. Keep it plain, factual, and short. "
        "Avoid jargon overload. Include clear next actions."
    )
    user = (
        "Draft an email with sections: Observation, Current Context, Next Steps.\n"
        f"Log metrics: total={result.total_lines}, severity={result.severity_counts}\n"
        f"Data mode={result.data_mode}\n"
        f"Likely environment failure reason={inference.reason} ({inference.confidence})\n"
        f"Top recurring errors={result.top_error_lines[:3]}\n"
        f"Issue clusters={result.issue_clusters[:3]}\n"
        f"First failing step={result.first_failing_step or 'Not provided'}\n"
        f"Test cases={result.top_test_cases[:3]}\n"
        f"Products={result.top_products[:3]}\n"
        f"Branches={result.top_branches[:3]}\n"
        f"Likely components={result.suspected_components[:3]}\n"
        f"Ongoing ticket={ticket_info or 'Not provided'}\n"
        f"Node history={node_history or 'Not provided'}\n"
        f"Verification results={verification_results or 'Not provided'}\n"
        f"Extra notes={extra_notes or 'None'}\n"
    )
    return call_openrouter(api_key=api_key, model=model, system_prompt=system, user_prompt=user)


def read_text_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


def read_csv_file(path: str) -> list[str]:
    rows: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        sample = f.read(2048)
        f.seek(0)
        try:
            has_header = csv.Sniffer().has_header(sample) if sample.strip() else False
        except csv.Error:
            has_header = False
        if has_header:
            reader = csv.DictReader(f)
            for row in reader:
                selected_keys = [
                    "time",
                    "verdict",
                    "origins_verdict",
                    "product",
                    "branch",
                    "tc_name",
                    "tc_id",
                    "node",
                    "environment",
                    "first_failing_step",
                    "first_error",
                    "cluster_id",
                    "fault_id",
                    "duration",
                    "duration_ts",
                    "jira_id",
                    "log_dir",
                ]
                selected = {
                    key: str(row.get(key, "") or "").strip()
                    for key in selected_keys
                    if str(row.get(key, "") or "").strip()
                }
                if selected:
                    rows.append(json.dumps(selected, ensure_ascii=False))
        else:
            reader = csv.reader(f)
            for row in reader:
                rows.append(" | ".join(row))
    return rows


def read_excel_file(path: str) -> list[str]:
    try:
        import pandas as pd
    except ImportError as e:
        raise RuntimeError(
            "Excel support requires pandas and openpyxl. Install requirements first."
        ) from e

    lines: list[str] = []
    sheets = pd.read_excel(path, sheet_name=None, dtype=str)
    for sheet_name, df in sheets.items():
        lines.append(f"sheet={sheet_name}")
        for _, row in df.fillna("").iterrows():
            values = [str(v) for v in row.tolist() if str(v).strip()]
            if values:
                lines.append(" | ".join(values))
    return lines


def read_input_file(path: str) -> list[str]:
    ext = os.path.splitext(path)[1].lower()
    if ext in {".log", ".txt"}:
        return read_text_file(path)
    if ext == ".csv":
        return read_csv_file(path)
    if ext in {".xlsx", ".xls"}:
        return read_excel_file(path)
    raise RuntimeError(
        f"Unsupported file type: {ext}. Supported: .log, .txt, .csv, .xlsx, .xls"
    )


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="ODLABOT log analyzer")
    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to input file (.log/.txt/.csv/.xlsx/.xls). If omitted, you will be prompted.",
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Enable OpenRouter LLM-enhanced analysis and summary.",
    )
    parser.add_argument(
        "--openrouter-model",
        default=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
        help="OpenRouter model id (default: openai/gpt-4o-mini).",
    )
    args = parser.parse_args()

    log_file = args.log_file or input(
        "Enter path to input file (.log/.txt/.csv/.xlsx/.xls): "
    ).strip()
    if not log_file:
        print("No log file provided.")
        return 1
    if not os.path.exists(log_file):
        print(f"File not found: {log_file}")
        return 1

    try:
        lines = read_input_file(log_file)
    except RuntimeError as e:
        print(str(e))
        return 1
    result = analyze_log(lines)

    print()
    print(format_analysis_summary(result))
    print()
    print(build_pod_investigation_guidance(result))
    print()
    print(build_search_guidance(result))
    print()

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    llm_enabled = args.use_llm
    if llm_enabled and not api_key:
        print("LLM requested but OPENROUTER_API_KEY is not set. Continuing without LLM.")
        llm_enabled = False

    if llm_enabled:
        print("LLM triage analysis:")
        print("-" * 72)
        try:
            llm_text = llm_enhanced_analysis(
                result=result, model=args.openrouter_model, api_key=api_key
            )
            print(llm_text)
        except (urllib.error.URLError, RuntimeError, json.JSONDecodeError) as e:
            print(f"OpenRouter call failed: {e}")
        print("-" * 72)
        print()

    print("Additional debugging context collection:")
    ticket_info = ""
    node_history = ""
    verification_results = ""
    extra_notes = ""

    if yes_no("Do you want to add ongoing ticket information?"):
        ticket_info = prompt_text("Ticket ID / current status")
    if yes_no("Do you want to add previous node/service history?"):
        node_history = prompt_text("History (recent incidents, changes, known behavior)")
    if yes_no("Do you want to add verification test results?"):
        verification_results = prompt_text("Verification results (pass/fail + details)")
    if yes_no("Do you want to add any extra debugging notes?"):
        extra_notes = prompt_text("Extra notes")

    print()
    print("Stakeholder-ready email summary:")
    print("-" * 72)
    if llm_enabled:
        try:
            print(
                llm_stakeholder_mail(
                    result=result,
                    ticket_info=ticket_info,
                    node_history=node_history,
                    verification_results=verification_results,
                    extra_notes=extra_notes,
                    model=args.openrouter_model,
                    api_key=api_key,
                )
            )
        except (urllib.error.URLError, RuntimeError, json.JSONDecodeError) as e:
            print(f"OpenRouter call failed for email draft: {e}")
            print(
                build_stakeholder_mail(
                    result, ticket_info, node_history, verification_results, extra_notes
                )
            )
    else:
        print(
            build_stakeholder_mail(
                result, ticket_info, node_history, verification_results, extra_notes
            )
        )
    print("-" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
