from collections import Counter, defaultdict
from typing import Any, Dict, List


SEVERITY_WEIGHT = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}


DRIVER_RULES = [
    {
        "name": "Weak account and password controls",
        "match_categories": {"account_management", "access_control"},
        "match_titles": {"password", "lockout", "account", "admin", "guest"},
    },
    {
        "name": "Remote access and session exposure",
        "match_categories": {"access_control", "secure_configuration"},
        "match_titles": {"rdp", "remote", "timeout", "inactivity"},
    },
    {
        "name": "Insecure workstation configuration",
        "match_categories": {"secure_configuration"},
        "match_titles": {"uac", "firewall", "autorun", "defender", "timeout", "password"},
    },
    {
        "name": "Sensitive or risky application exposure",
        "match_categories": {"application_security", "data_protection"},
        "match_titles": {"application", "software", "browser", "vpn", "remote", "steam", "chrome", "edge"},
    },
    {
        "name": "Patch and update visibility gaps",
        "match_categories": {"patching"},
        "match_titles": {"update", "patch", "hotfix"},
    },
    {
        "name": "Audit and recovery visibility weaknesses",
        "match_categories": {"logging", "data_protection"},
        "match_titles": {"audit", "backup", "log"},
    },
]


REMEDIATION_PLAYBOOK = [
    {
        "key": "account_policy",
        "title": "Harden account policy and password controls",
        "keywords": {"password", "lockout", "account", "admin", "guest", "complexity"},
        "categories": {"account_management", "access_control", "secure_configuration"},
    },
    {
        "key": "remote_access",
        "title": "Review and restrict remote access exposure",
        "keywords": {"rdp", "remote", "timeout", "inactivity"},
        "categories": {"access_control", "secure_configuration"},
    },
    {
        "key": "workstation_hardening",
        "title": "Harden endpoint security configuration",
        "keywords": {"uac", "firewall", "defender", "autorun", "timeout"},
        "categories": {"secure_configuration"},
    },
    {
        "key": "software_review",
        "title": "Review risky or sensitive software exposure",
        "keywords": {"software", "application", "browser", "vpn", "steam", "chrome", "edge"},
        "categories": {"application_security", "data_protection"},
    },
    {
        "key": "patch_visibility",
        "title": "Improve patch and update visibility",
        "keywords": {"update", "patch", "hotfix"},
        "categories": {"patching"},
    },
    {
        "key": "audit_recovery",
        "title": "Strengthen audit logging and recovery readiness",
        "keywords": {"audit", "backup", "log"},
        "categories": {"logging", "data_protection"},
    },
]


def _normalized_text(finding: Dict[str, Any]) -> str:
    title = str(finding.get("title", "")).lower()
    description = str(finding.get("description", "")).lower()
    recommendation = str(finding.get("recommendation", "")).lower()
    return f"{title} {description} {recommendation}"


def group_findings_by_host(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        hostname = str(finding.get("hostname", "unknown")).strip() or "unknown"
        grouped[hostname].append(finding)

    return dict(grouped)


def summarize_host_findings(hostname: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity_counts = Counter()
    category_counts = Counter()
    control_counts = Counter()
    weighted_score = 0
    supporting_findings = []

    for finding in findings:
        severity = str(finding.get("severity", "low")).lower()
        category = str(finding.get("category", "unknown"))
        controls = finding.get("cis_controls", [])

        severity_counts[severity] += 1
        category_counts[category] += 1
        weighted_score += SEVERITY_WEIGHT.get(severity, 0)

        if isinstance(controls, list):
            for control in controls:
                if control:
                    control_counts[str(control)] += 1

        finding_id = finding.get("finding_id")
        if isinstance(finding_id, str) and finding_id.strip():
            supporting_findings.append(finding_id)

    risk_level = derive_risk_level(weighted_score, severity_counts)

    return {
        "hostname": hostname,
        "finding_count": len(findings),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "control_counts": dict(control_counts),
        "weighted_score": weighted_score,
        "risk_level": risk_level,
        "supporting_findings": supporting_findings[:5],
    }


def derive_risk_level(weighted_score: int, severity_counts: Counter) -> str:
    if severity_counts.get("critical", 0) >= 2 or weighted_score >= 30:
        return "critical"
    if severity_counts.get("critical", 0) >= 1 or severity_counts.get("high", 0) >= 2 or weighted_score >= 18:
        return "high"
    if severity_counts.get("medium", 0) >= 2 or weighted_score >= 8:
        return "medium"
    return "low"


def detect_risk_drivers(findings: List[Dict[str, Any]]) -> List[str]:
    matched = []

    for rule in DRIVER_RULES:
        hits = 0
        for finding in findings:
            category = str(finding.get("category", "")).strip()
            text = _normalized_text(finding)

            category_match = category in rule["match_categories"]
            keyword_match = any(keyword in text for keyword in rule["match_titles"])

            if category_match or keyword_match:
                hits += 1

        if hits > 0:
            matched.append((rule["name"], hits))

    matched.sort(key=lambda item: item[1], reverse=True)
    return [name for name, _count in matched[:3]]


def build_remediation_candidates(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates = []

    for play in REMEDIATION_PLAYBOOK:
        matched_findings = []
        categories = set()
        controls = set()
        score = 0

        for finding in findings:
            text = _normalized_text(finding)
            category = str(finding.get("category", "")).strip()

            keyword_match = any(keyword in text for keyword in play["keywords"])
            category_match = category in play["categories"]

            if keyword_match or category_match:
                matched_findings.append(finding)
                categories.add(category)

                for control in finding.get("cis_controls", []):
                    if control:
                        controls.add(str(control))

                severity = str(finding.get("severity", "low")).lower()
                score += SEVERITY_WEIGHT.get(severity, 0)

        if matched_findings:
            candidates.append({
                "key": play["key"],
                "title": play["title"],
                "score": score,
                "categories": sorted(c for c in categories if c),
                "controls": sorted(controls),
                "findings": matched_findings,
            })

    candidates.sort(key=lambda item: item["score"], reverse=True)
    return candidates


def top_categories(category_counts: Dict[str, int], limit: int = 3) -> List[str]:
    return [name for name, _count in sorted(category_counts.items(), key=lambda item: item[1], reverse=True)[:limit]]


def top_controls(control_counts: Dict[str, int], limit: int = 3) -> List[str]:
    return [name for name, _count in sorted(control_counts.items(), key=lambda item: item[1], reverse=True)[:limit]]