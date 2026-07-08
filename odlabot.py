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


BUCKET_FIELDS = ["time", "started"]

BUILD_VERSION_FIELDS = [
    "beets", "tacos", "new_beets", "dallas",
    "helm_chart", "from_helm_chart", "pcc_framework",
]

BUILD_FAILURE_KEYWORDS = re.compile(
    r"\b(install|installation|deploy|deployment|helm|chart|dallas|beets|tacos|"
    r"upgrade|rollout|image|pull|push|registry|artifact|package|rpm|deb|binary|"
    r"version mismatch|build failed|build error|not found|no such image)\b",
    re.IGNORECASE,
)


@dataclasses.dataclass
class FailureTrendResult:
    # ordered list of (hour_bucket_str, failure_count)
    hourly_buckets: list[tuple[str, int]]
    # hour bucket where failures first appeared
    first_failure_hour: str
    # hour bucket with the peak failure count
    peak_failure_hour: str
    peak_failure_count: int
    # True if the last half of buckets has a higher avg than the first half
    is_accelerating: bool
    # build version seen at first failure hour {component: version}
    build_at_first_failure: dict[str, str]


@dataclasses.dataclass
class DurationAnomalyResult:
    median_duration: float
    p95_duration: float
    outliers: list[tuple[str, float]]  # (tc_name, duration_minutes)
    has_anomalies: bool


@dataclasses.dataclass
class BuildIntroductionResult:
    # {component: {version: first_failure_hour}}
    first_failure_per_version: dict[str, dict[str, str]]
    # component + version most likely to have introduced failures
    suspected_build: str


@dataclasses.dataclass
class FlakyTestResult:
    # {tc_name: {"passed": n, "failed": n}}
    flaky_tests: dict[str, dict[str, int]]
    consistently_failing: list[str]


@dataclasses.dataclass
class JiraGroupResult:
    # {jira_id: list of tc_names}
    jira_groups: dict[str, list[str]]
    untracked_count: int


@dataclasses.dataclass
class NodeIsolationResult:
    # {node: failure_count}
    node_failure_counts: dict[str, int]
    # {cluster_id: failure_count}
    cluster_failure_counts: dict[str, int]
    is_isolated_to_single_node: bool
    is_isolated_to_single_cluster: bool
    dominant_node: str
    dominant_cluster: str


@dataclasses.dataclass
class FailingStepGroupResult:
    # [(first_failing_step, first_error, count)]
    step_groups: list[tuple[str, str, int]]


@dataclasses.dataclass
class BuildConsistencyResult:
    # {component: Counter{version: count}}
    version_distributions: dict[str, collections.Counter]
    # components where more than one distinct non-empty version was seen
    mismatched: list[str]
    # components where all rows share exactly one version
    consistent: list[str]
    is_build_suspect: bool


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
    build_consistency: BuildConsistencyResult | None
    failure_trend: FailureTrendResult | None
    duration_anomalies: DurationAnomalyResult | None
    build_introduction: BuildIntroductionResult | None
    flaky_tests: FlakyTestResult | None
    jira_groups: JiraGroupResult | None
    node_isolation: NodeIsolationResult | None
    failing_step_groups: FailingStepGroupResult | None


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


def _parse_hour_bucket(line: str) -> str | None:
    """Extract an hour-level bucket string (YYYY-MM-DD HH) from a JSON log line or raw text."""
    for field in BUCKET_FIELDS:
        value = extract_field(line, [field])
        if value:
            m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2})", value)
            if m:
                return f"{m.group(1)} {m.group(2)}:00"
    # fallback: scan raw text for a timestamp
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}):\d{2}", line)
    if m:
        return f"{m.group(1)} {m.group(2)}:00"
    return None


def analyze_failure_trend(
    lines: list[str],
    build_version_counters: dict[str, collections.Counter],
) -> FailureTrendResult | None:
    # bucket_failures: {hour_bucket: failure_count}
    bucket_failures: collections.Counter[str] = collections.Counter()
    # bucket_builds: {hour_bucket: {component: Counter{version}}}
    bucket_builds: dict[str, dict[str, collections.Counter]] = {}

    for line in lines:
        lower = line.lower()
        is_error_like = any(
            pat.search(lower)
            for sev, pat in SEVERITY_PATTERNS.items()
            if sev in {"fatal", "error", "timeout"}
        )
        bucket = _parse_hour_bucket(line)
        if bucket is None:
            continue
        if is_error_like:
            bucket_failures[bucket] += 1
        if bucket not in bucket_builds:
            bucket_builds[bucket] = {f: collections.Counter() for f in BUILD_VERSION_FIELDS}
        for field in BUILD_VERSION_FIELDS:
            val = extract_field(line, [field])
            if val and val not in ("", "N/A", "n/a", "na", "none", "null"):
                bucket_builds[bucket][field][val] += 1

    if not bucket_failures:
        return None

    sorted_buckets = sorted(bucket_failures.items())
    first_failure_hour = sorted_buckets[0][0]
    peak_hour, peak_count = max(sorted_buckets, key=lambda x: x[1])

    counts = [c for _, c in sorted_buckets]
    mid = max(len(counts) // 2, 1)
    first_half_avg = sum(counts[:mid]) / mid
    second_half_avg = sum(counts[mid:]) / max(len(counts[mid:]), 1)
    is_accelerating = second_half_avg > first_half_avg

    build_at_first = {}
    if first_failure_hour in bucket_builds:
        for component, counter in bucket_builds[first_failure_hour].items():
            if counter:
                top_version = counter.most_common(1)[0][0]
                build_at_first[component] = top_version

    return FailureTrendResult(
        hourly_buckets=sorted_buckets,
        first_failure_hour=first_failure_hour,
        peak_failure_hour=peak_hour,
        peak_failure_count=peak_count,
        is_accelerating=is_accelerating,
        build_at_first_failure=build_at_first,
    )


def format_failure_trend_summary(ft: FailureTrendResult) -> str:
    lines = ["Failure trend over time:"]
    lines.append(f"- First failure hour : {ft.first_failure_hour}")
    lines.append(f"- Peak failure hour  : {ft.peak_failure_hour} ({ft.peak_failure_count} failures)")
    lines.append(
        f"- Trend direction    : {'ACCELERATING ↑ (failures increasing over time)' if ft.is_accelerating else 'STABLE / DECLINING ↓'}"
    )
    if ft.build_at_first_failure:
        lines.append("- Build at first failure hour:")
        for component, version in ft.build_at_first_failure.items():
            lines.append(f"    {component}: {version}")
    lines.append("- Hourly breakdown:")
    max_count = max(c for _, c in ft.hourly_buckets)
    bar_width = 30
    for bucket, count in ft.hourly_buckets:
        bar_len = max(1, round(count / max_count * bar_width))
        bar = "█" * bar_len
        lines.append(f"    {bucket}  {bar} {count}")
    return "\n".join(lines)


def is_build_related_error(result: AnalysisResult) -> bool:
    """Returns True if first_failing_step or top errors contain build-related keywords."""
    texts = [result.first_failing_step, result.first_failure_line]
    texts += [msg for msg, _ in result.top_error_lines[:3]]
    return any(BUILD_FAILURE_KEYWORDS.search(t) for t in texts if t)


def analyze_duration_anomalies(lines: list[str]) -> DurationAnomalyResult | None:
    durations: list[tuple[str, float]] = []
    for line in lines:
        raw = extract_field(line, ["duration"])
        tc = extract_field(line, ["tc_name", "test_case", "testcase"]) or "unknown"
        if raw:
            try:
                val = float(raw)
                if val > 0:
                    durations.append((tc, val))
            except ValueError:
                pass
    if len(durations) < 3:
        return None
    vals = sorted(v for _, v in durations)
    median = vals[len(vals) // 2]
    p95 = vals[int(len(vals) * 0.95)]
    threshold = max(median * 3.0, p95)
    outliers = [(tc, v) for tc, v in durations if v >= threshold]
    outliers.sort(key=lambda x: x[1], reverse=True)
    return DurationAnomalyResult(
        median_duration=round(median, 2),
        p95_duration=round(p95, 2),
        outliers=outliers[:10],
        has_anomalies=len(outliers) > 0,
    )


def format_duration_anomaly_summary(da: DurationAnomalyResult) -> str:
    lines = ["Duration anomaly check:"]
    lines.append(f"- Median duration : {da.median_duration} min")
    lines.append(f"- P95 duration    : {da.p95_duration} min")
    if da.has_anomalies:
        lines.append(f"- Outliers (>= {max(da.median_duration * 3, da.p95_duration):.1f} min):")
        for tc, val in da.outliers:
            lines.append(f"  - {tc}: {val} min")
    else:
        lines.append("- No duration outliers detected.")
    return "\n".join(lines)


def analyze_build_introduction(
    lines: list[str],
    build_version_counters: dict[str, collections.Counter],
) -> BuildIntroductionResult | None:
    # {component: {version: earliest_failure_hour}}
    first_failure_per_version: dict[str, dict[str, str]] = {}
    for line in lines:
        lower = line.lower()
        is_error_like = any(
            pat.search(lower)
            for sev, pat in SEVERITY_PATTERNS.items()
            if sev in {"fatal", "error", "timeout"}
        )
        if not is_error_like:
            continue
        bucket = _parse_hour_bucket(line)
        if not bucket:
            continue
        for field in BUILD_VERSION_FIELDS:
            val = extract_field(line, [field])
            if not val or val in ("", "N/A", "n/a", "na", "none", "null"):
                continue
            if field not in first_failure_per_version:
                first_failure_per_version[field] = {}
            existing = first_failure_per_version[field].get(val)
            if existing is None or bucket < existing:
                first_failure_per_version[field][val] = bucket
    if not first_failure_per_version:
        return None
    # find the component+version whose first failure hour is earliest
    earliest_hour = None
    suspected_build = "unknown"
    for component, version_map in first_failure_per_version.items():
        for version, hour in version_map.items():
            if earliest_hour is None or hour < earliest_hour:
                earliest_hour = hour
                suspected_build = f"{component}={version} (first failure: {hour})"
    return BuildIntroductionResult(
        first_failure_per_version=first_failure_per_version,
        suspected_build=suspected_build,
    )


def format_build_introduction_summary(bi: BuildIntroductionResult) -> str:
    lines = ["Build introduction check:"]
    lines.append(f"- Most likely introducing build: {bi.suspected_build}")
    for component, version_map in bi.first_failure_per_version.items():
        for version, hour in sorted(version_map.items(), key=lambda x: x[1]):
            lines.append(f"  - {component}={version}  first failure at {hour}")
    return "\n".join(lines)


def analyze_flaky_tests(lines: list[str]) -> FlakyTestResult | None:
    tc_verdicts: dict[str, collections.Counter] = {}
    for line in lines:
        tc = extract_field(line, ["tc_name", "test_case", "testcase"])
        verdict = extract_field(line, ["verdict"])
        if not tc or not verdict:
            continue
        norm = normalize_verdict(verdict)
        if tc not in tc_verdicts:
            tc_verdicts[tc] = collections.Counter()
        if norm in PASS_LIKE_VALUES:
            tc_verdicts[tc]["passed"] += 1
        elif norm in FAIL_LIKE_VALUES:
            tc_verdicts[tc]["failed"] += 1
    if not tc_verdicts:
        return None
    flaky: dict[str, dict[str, int]] = {}
    consistently_failing: list[str] = []
    for tc, counter in tc_verdicts.items():
        has_pass = counter.get("passed", 0) > 0
        has_fail = counter.get("failed", 0) > 0
        if has_pass and has_fail:
            flaky[tc] = dict(counter)
        elif has_fail and not has_pass:
            consistently_failing.append(tc)
    return FlakyTestResult(flaky_tests=flaky, consistently_failing=consistently_failing)


def format_flaky_test_summary(ft: FlakyTestResult) -> str:
    lines = ["Flaky test detection:"]
    if ft.flaky_tests:
        lines.append(f"- {len(ft.flaky_tests)} flaky test(s) detected (mixed pass/fail across runs):")
        for tc, counts in sorted(ft.flaky_tests.items(), key=lambda x: x[1].get("failed", 0), reverse=True):
            lines.append(f"  - {tc}  passed={counts.get('passed',0)}, failed={counts.get('failed',0)}")
    else:
        lines.append("- No flaky tests detected.")
    if ft.consistently_failing:
        lines.append(f"- {len(ft.consistently_failing)} consistently failing test(s):")
        for tc in ft.consistently_failing[:10]:
            lines.append(f"  - {tc}")
    return "\n".join(lines)


def analyze_jira_groups(lines: list[str]) -> JiraGroupResult | None:
    jira_groups: dict[str, list[str]] = {}
    untracked = 0
    for line in lines:
        tc = extract_field(line, ["tc_name", "test_case", "testcase"])
        if not tc:
            continue
        verdict = extract_field(line, ["verdict"])
        if verdict and normalize_verdict(verdict) not in FAIL_LIKE_VALUES:
            continue
        jira = extract_field(line, ["jira_id"])
        if jira and jira.strip():
            if jira not in jira_groups:
                jira_groups[jira] = []
            if tc not in jira_groups[jira]:
                jira_groups[jira].append(tc)
        else:
            untracked += 1
    if not jira_groups and untracked == 0:
        return None
    return JiraGroupResult(jira_groups=jira_groups, untracked_count=untracked)


def format_jira_group_summary(jg: JiraGroupResult) -> str:
    lines = ["JIRA ID grouping:"]
    if jg.jira_groups:
        for jira_id, tcs in sorted(jg.jira_groups.items()):
            lines.append(f"  - {jira_id} ({len(tcs)} test case(s)):")
            for tc in tcs[:5]:
                lines.append(f"      {tc}")
    else:
        lines.append("- No JIRA IDs found in failing rows.")
    lines.append(f"- Untracked failures (no jira_id): {jg.untracked_count}")
    return "\n".join(lines)


def analyze_node_isolation(lines: list[str]) -> NodeIsolationResult | None:
    node_counter: collections.Counter[str] = collections.Counter()
    cluster_counter: collections.Counter[str] = collections.Counter()
    for line in lines:
        verdict = extract_field(line, ["verdict"])
        if verdict and normalize_verdict(verdict) not in FAIL_LIKE_VALUES:
            continue
        node = extract_field(line, ["node", "host", "hostname"])
        cluster = extract_field(line, ["cluster_id"])
        if node:
            node_counter[node] += 1
        if cluster:
            cluster_counter[cluster] += 1
    if not node_counter and not cluster_counter:
        return None
    dominant_node = node_counter.most_common(1)[0][0] if node_counter else "unknown"
    dominant_cluster = cluster_counter.most_common(1)[0][0] if cluster_counter else "unknown"
    total_node_failures = sum(node_counter.values()) or 1
    total_cluster_failures = sum(cluster_counter.values()) or 1
    top_node_share = node_counter.most_common(1)[0][1] / total_node_failures if node_counter else 0
    top_cluster_share = cluster_counter.most_common(1)[0][1] / total_cluster_failures if cluster_counter else 0
    return NodeIsolationResult(
        node_failure_counts=dict(node_counter.most_common(8)),
        cluster_failure_counts=dict(cluster_counter.most_common(8)),
        is_isolated_to_single_node=top_node_share >= 0.9 and len(node_counter) == 1,
        is_isolated_to_single_cluster=top_cluster_share >= 0.9 and len(cluster_counter) == 1,
        dominant_node=dominant_node,
        dominant_cluster=dominant_cluster,
    )


def format_node_isolation_summary(ni: NodeIsolationResult) -> str:
    lines = ["Node / cluster isolation check:"]
    if ni.is_isolated_to_single_node:
        lines.append(f"- ISOLATED: All failures on single node '{ni.dominant_node}' — likely an infra issue on that node.")
    elif ni.node_failure_counts:
        lines.append(f"- Failures spread across {len(ni.node_failure_counts)} node(s):")
        for node, count in ni.node_failure_counts.items():
            lines.append(f"  - {node}: {count} failure(s)")
    if ni.is_isolated_to_single_cluster:
        lines.append(f"- ISOLATED: All failures on single cluster '{ni.dominant_cluster}'.")
    elif ni.cluster_failure_counts:
        lines.append(f"- Failures spread across {len(ni.cluster_failure_counts)} cluster(s):")
        for cluster, count in ni.cluster_failure_counts.items():
            lines.append(f"  - {cluster}: {count} failure(s)")
    return "\n".join(lines)


def analyze_failing_step_groups(lines: list[str]) -> FailingStepGroupResult | None:
    # group by (first_failing_step, first_error) and count
    group_counter: collections.Counter[tuple[str, str]] = collections.Counter()
    for line in lines:
        verdict = extract_field(line, ["verdict"])
        if verdict and normalize_verdict(verdict) not in FAIL_LIKE_VALUES:
            continue
        step = extract_field(line, ["first_failing_step"]) or ""
        error = extract_field(line, ["first_error"]) or ""
        if step or error:
            group_counter[(step[:120], error[:120])] += 1
    if not group_counter:
        return None
    return FailingStepGroupResult(
        step_groups=[
            (step, error, count)
            for (step, error), count in group_counter.most_common(10)
        ]
    )


def format_failing_step_groups_summary(fg: FailingStepGroupResult) -> str:
    lines = ["Failing step pattern groups:"]
    for idx, (step, error, count) in enumerate(fg.step_groups, start=1):
        lines.append(f"  {idx}. [{count}x] step: {step or '(none)'}")
        if error:
            lines.append(f"         error: {error}")
    return "\n".join(lines)


def analyze_build_consistency(
    version_distributions: dict[str, collections.Counter],
) -> BuildConsistencyResult:
    mismatched = []
    consistent = []
    for component, counter in version_distributions.items():
        versions = [v for v in counter if v not in ("", "N/A", "n/a", "na", "none", "null")]
        if len(versions) > 1:
            mismatched.append(component)
        elif len(versions) == 1:
            consistent.append(component)
    # If all components are on the same version, a single bad build may be the root cause.
    # Mixed versions means failures span multiple builds, making it less likely to be build-related.
    return BuildConsistencyResult(
        version_distributions=version_distributions,
        mismatched=mismatched,
        consistent=consistent,
        is_build_suspect=len(mismatched) == 0 and len(consistent) > 0,
    )


def format_build_consistency_summary(bc: BuildConsistencyResult) -> str:
    lines = ["Build consistency check:"]
    if not bc.version_distributions:
        lines.append("- No build version fields detected in this file.")
        return "\n".join(lines)
    if bc.is_build_suspect:
        lines.append(
            "- NOTE: All build components are on the same version across all rows."
            " This may indicate a build-related issue (one bad build affecting all runs)."
        )
    elif bc.mismatched:
        lines.append(
            f"- Builds are mixed across {len(bc.mismatched)} component(s)."
            " Failures span multiple builds, so a single build regression is less likely."
        )
    for component in bc.consistent:
        counter = bc.version_distributions[component]
        version = next(
            (v for v in counter if v not in ("", "N/A", "n/a", "none", "null")), "unknown"
        )
        lines.append(f"  - SAME      {component}: {version}")
    for component in bc.mismatched:
        counter = bc.version_distributions[component]
        version_summary = ", ".join(
            f"{v}({c})" for v, c in counter.most_common() if v not in ("", "N/A", "n/a")
        )
        lines.append(f"  - MIXED     {component}: {version_summary}")
    return "\n".join(lines)


def analyze_log(lines: Iterable[str]) -> AnalysisResult:
    all_lines: list[str] = list(lines)
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
    build_version_counters: dict[str, collections.Counter] = {
        f: collections.Counter() for f in BUILD_VERSION_FIELDS
    }
    timestamps: list[str] = []
    total = 0
    first_failure_timestamp = ""
    first_failing_step = ""
    first_failure_line = ""

    for raw in all_lines:
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

        for build_field in BUILD_VERSION_FIELDS:
            bv = extract_field(line, [build_field])
            if bv:
                build_version_counters[build_field][bv] += 1

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

    active_build_counters = {
        f: c for f, c in build_version_counters.items() if c
    }
    build_consistency = (
        analyze_build_consistency(active_build_counters) if active_build_counters else None
    )
    failure_trend = analyze_failure_trend(all_lines, build_version_counters)
    duration_anomalies = analyze_duration_anomalies(all_lines)
    build_introduction = analyze_build_introduction(all_lines, build_version_counters)
    flaky_tests = analyze_flaky_tests(all_lines)
    jira_groups = analyze_jira_groups(all_lines)
    node_isolation = analyze_node_isolation(all_lines)
    failing_step_groups = analyze_failing_step_groups(all_lines)

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
        build_consistency=build_consistency,
        failure_trend=failure_trend,
        duration_anomalies=duration_anomalies,
        build_introduction=build_introduction,
        flaky_tests=flaky_tests,
        jira_groups=jira_groups,
        node_isolation=node_isolation,
        failing_step_groups=failing_step_groups,
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
        f"1) Broad scan: rg -n -i \"error|exception|fatal|timeout|failed\" <logfile>",
        f"2) Dominant failure: rg -n -i \"{term_string}\" <logfile>",
        f"3) Affected workload: rg -n -i \"{primary_service}|{primary_node}|{primary_pod}\" <logfile>",
        f"4) First failure window: around {first_failure_ts} (+2-5 min)",
        f"5) Exact signature count: rg -n -F \"{exact_signature}\" <logfile>",
    ]
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
    verdicts = ", ".join([f"{name}={count}" for name, count in sorted(result.verdict_counts.items())]) or "N/A"

    def format_top_items(items: list[tuple[str, int]], limit: int = 5) -> str:
        return ", ".join([f"{name}({count})" for name, count in items[:limit]])

    lines = [
        "Technical summary:",
        f"- Lines: {result.total_lines}  |  Mode: {result.data_mode}  |  Verdicts: {verdicts}",
        (
            f"- Severity: fatal={sev['fatal']}, error={sev['error']}, "
            f"timeout={sev['timeout']}, warning={sev['warning']}"
        ),
        f"- Likely root cause: {inference.reason} ({inference.confidence} confidence)",
        f"- {inference.explanation}",
    ]
    if result.first_failure_timestamp:
        lines.append(f"- First failure: {result.first_failure_timestamp}  |  Step: {result.first_failing_step or 'N/A'}")
    if result.first_failure_line:
        lines.append(f"- First failure signature: {result.first_failure_line}")
    if result.top_test_cases:
        lines.append(f"- Top test cases: {format_top_items(result.top_test_cases)}")
    if result.top_products or result.top_branches:
        lines.append(
            f"- Product: {format_top_items(result.top_products)}  |  Branch: {format_top_items(result.top_branches)}"
        )
    if result.top_cluster_ids or result.top_fault_ids:
        lines.append(
            f"- Clusters: {format_top_items(result.top_cluster_ids)}  |  Fault IDs: {format_top_items(result.top_fault_ids)}"
        )
    if result.top_nodes:
        lines.append(f"- Nodes with most failures: {format_top_items(result.top_nodes)}")
    if result.top_error_lines:
        lines.append(f"- Repeated failure ratio: {result.repeated_failure_ratio:.1%}")
        lines.append("- Top recurring failures:")
        for msg, count in result.top_error_lines[:5]:
            lines.append(f"  [{count}x] {msg}")
    if result.issue_clusters:
        lines.append("- Issue clusters:")
        for scope, category, signature, count in result.issue_clusters[:5]:
            lines.append(f"  [{count}x] {scope} | {category} | {signature}")
    if result.build_consistency:
        lines.append("")
        lines.append(format_build_consistency_summary(result.build_consistency))
    if result.failure_trend:
        lines.append("")
        lines.append(format_failure_trend_summary(result.failure_trend))
    if result.duration_anomalies and result.duration_anomalies.has_anomalies:
        lines.append("")
        lines.append(format_duration_anomaly_summary(result.duration_anomalies))
    if result.build_introduction:
        lines.append("")
        lines.append(format_build_introduction_summary(result.build_introduction))
    if result.flaky_tests and (result.flaky_tests.flaky_tests or result.flaky_tests.consistently_failing):
        lines.append("")
        lines.append(format_flaky_test_summary(result.flaky_tests))
    if result.jira_groups:
        lines.append("")
        lines.append(format_jira_group_summary(result.jira_groups))
    if result.node_isolation:
        lines.append("")
        lines.append(format_node_isolation_summary(result.node_isolation))
    if result.failing_step_groups:
        lines.append("")
        lines.append(format_failing_step_groups_summary(result.failing_step_groups))
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
    ]
    if result.build_consistency and result.build_consistency.is_build_suspect:
        mail.append(
            f"- Build versions are consistent across all rows ({', '.join(result.build_consistency.consistent)})"
            " — a build-related root cause cannot be ruled out."
        )
    mail += [
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
        f"Build consistency: {format_build_consistency_summary(result.build_consistency) if result.build_consistency else 'N/A'}\n"
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


def llm_what_happened(result: AnalysisResult, model: str, api_key: str) -> str:
    inference = infer_likely_environment_failure(result)
    system = "You are a concise incident summarizer. Write plain English only. No bullet points, no headers, no markdown."
    user = (
        "Write a 3-5 sentence plain English paragraph explaining what happened based on this data. "
        "Start with what failed, how many times, then the most likely reason, then what should be checked first.\n"
        f"Total failures: {sum(result.severity_counts.values())}\n"
        f"Data mode: {result.data_mode}\n"
        f"Likely reason: {inference.reason} ({inference.confidence} confidence)\n"
        f"Top error: {result.top_error_lines[0][0] if result.top_error_lines else 'unknown'}\n"
        f"First failing step: {result.first_failing_step or 'unknown'}\n"
        f"Top test case: {result.top_test_cases[0][0] if result.top_test_cases else 'unknown'}\n"
        f"Node: {result.top_nodes[0][0] if result.top_nodes else 'unknown'}\n"
        f"Build suspect: {result.build_consistency.is_build_suspect if result.build_consistency else False}\n"
        f"Flaky tests: {len(result.flaky_tests.flaky_tests) if result.flaky_tests else 0}\n"
        f"Node isolated: {result.node_isolation.is_isolated_to_single_node if result.node_isolation else False}\n"
    )
    return call_openrouter(api_key=api_key, model=model, system_prompt=system, user_prompt=user)


def llm_triage_checklist(result: AnalysisResult, model: str, api_key: str) -> str:
    inference = infer_likely_environment_failure(result)
    system = "You are a triage engineer. Output a numbered checklist only. Each item must be one specific actionable step. No explanations."
    flaky = list((result.flaky_tests.flaky_tests or {}).keys())[:3] if result.flaky_tests else []
    node = result.node_isolation.dominant_node if result.node_isolation else None
    build = result.build_consistency.consistent[:2] if result.build_consistency and result.build_consistency.is_build_suspect else []
    user = (
        "Generate a numbered triage checklist (max 8 steps) based on these findings.\n"
        f"Likely reason: {inference.reason}\n"
        f"First failing step: {result.first_failing_step or 'unknown'}\n"
        f"Top error: {result.top_error_lines[0][0] if result.top_error_lines else 'unknown'}\n"
        f"Flaky tests found: {flaky}\n"
        f"Dominant node: {node or 'spread across nodes'}\n"
        f"Build suspect components: {build}\n"
        f"Untracked JIRA failures: {result.jira_groups.untracked_count if result.jira_groups else 0}\n"
        f"Duration outliers: {[tc for tc, _ in (result.duration_anomalies.outliers[:3] if result.duration_anomalies else [])]}\n"
        f"Top issue clusters: {[(s, c) for s, _, _, c in result.issue_clusters[:3]]}\n"
    )
    return call_openrouter(api_key=api_key, model=model, system_prompt=system, user_prompt=user)


def llm_root_cause_scorecard(result: AnalysisResult, model: str, api_key: str) -> str:
    inference = infer_likely_environment_failure(result)
    build_error_confirmed = is_build_related_error(result)
    system = "You are a root cause analyst. Output a scorecard table only. For each hypothesis rate it HIGH/MEDIUM/LOW and give one supporting evidence line."
    user = (
        "Rate these 4 hypotheses — Build Issue, Environment/Infra Issue, Flaky Test, Node Isolation — "
        "as HIGH/MEDIUM/LOW likelihood based on evidence. Format: Hypothesis | Rating | Evidence\n"
        "IMPORTANT RULE: Build Issue is only HIGH if ALL of these are true: "
        "(1) all rows share the same build version, "
        "(2) the first_failing_step or error text contains build-related keywords like install/deploy/helm/dallas/image. "
        "Mixed build versions means Build Issue is LOW. Same version but no build error keywords means MEDIUM at most.\n"
        f"Build consistency (same across all rows): {result.build_consistency.is_build_suspect if result.build_consistency else False}\n"
        f"Build error keywords found in errors: {build_error_confirmed}\n"
        f"First failing step: {result.first_failing_step or 'unknown'}\n"
        f"Top error: {result.top_error_lines[0][0] if result.top_error_lines else 'unknown'}\n"
        f"Flaky tests: {len(result.flaky_tests.flaky_tests) if result.flaky_tests else 0}\n"
        f"Node isolated: {result.node_isolation.is_isolated_to_single_node if result.node_isolation else False}\n"
        f"Dominant node: {result.node_isolation.dominant_node if result.node_isolation else 'N/A'}\n"
        f"Dominant failure category: {inference.reason}\n"
        f"Confidence: {inference.confidence}\n"
        f"Repeated failure ratio: {result.repeated_failure_ratio}\n"
    )
    return call_openrouter(api_key=api_key, model=model, system_prompt=system, user_prompt=user)


def llm_cluster_explanations(result: AnalysisResult, model: str, api_key: str) -> str:
    if not result.issue_clusters:
        return ""
    system = "You are a log analyst. For each cluster, write one plain English sentence explaining what likely happened. No bullet formatting — use numbered list only."
    clusters_text = "\n".join(
        f"{i}. scope={scope}, category={category}, count={count}, signature={sig[:120]}"
        for i, (scope, category, sig, count) in enumerate(result.issue_clusters[:6], start=1)
    )
    user = f"Explain each of these failure clusters in one plain sentence:\n{clusters_text}"
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
                ] + BUILD_VERSION_FIELDS
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
