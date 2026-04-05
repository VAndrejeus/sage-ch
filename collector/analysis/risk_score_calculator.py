from typing import Any, Dict, List


SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
}


def calculate_host_risk_scores(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    host_scores: Dict[str, Dict[str, Any]] = {}

    for finding in findings:
        hostname = finding.get("hostname", "unknown")
        severity = str(finding.get("severity", "")).lower()
        weight = SEVERITY_WEIGHTS.get(severity, 0)

        if hostname not in host_scores:
            host_scores[hostname] = {
                "hostname": hostname,
                "raw_score": 0,
                "risk_score": 0,
                "risk_level": "low",
                "finding_count": 0,
                "severity_breakdown": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
            }

        host_scores[hostname]["raw_score"] += weight
        host_scores[hostname]["finding_count"] += 1

        if severity in host_scores[hostname]["severity_breakdown"]:
            host_scores[hostname]["severity_breakdown"][severity] += 1

    for hostname, data in host_scores.items():
        capped_score = min(data["raw_score"], 100)
        data["risk_score"] = capped_score
        data["risk_level"] = get_risk_level(capped_score)

    return dict(sorted(host_scores.items()))


def get_risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "elevated"
    if score >= 1:
        return "guarded"
    return "low"