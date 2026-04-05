from typing import Any, Dict, List, Set

from collector.analysis.rules import get_all_rules


def calculate_control_scores(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    enabled_rules = get_all_rules(enabled_only=True)

    control_to_rule_ids: Dict[str, Set[str]] = {}
    for rule in enabled_rules:
        for control in rule.cis_controls:
            if control not in control_to_rule_ids:
                control_to_rule_ids[control] = set()
            control_to_rule_ids[control].add(rule.rule_id)

    control_to_failed_rule_ids: Dict[str, Set[str]] = {}
    for finding in findings:
        rule_id = finding.get("rule_id")
        for control in finding.get("cis_controls", []):
            if control not in control_to_failed_rule_ids:
                control_to_failed_rule_ids[control] = set()
            if rule_id:
                control_to_failed_rule_ids[control].add(rule_id)

    control_scores: Dict[str, Dict[str, Any]] = {}

    for control in sorted(control_to_rule_ids.keys()):
        total_rules = len(control_to_rule_ids[control])
        failed_rules = len(control_to_failed_rule_ids.get(control, set()))
        passed_rules = total_rules - failed_rules

        if total_rules == 0:
            score = 100
        else:
            score = round((passed_rules / total_rules) * 100, 2)

        if score == 100:
            status = "pass"
        elif score >= 50:
            status = "partial"
        else:
            status = "fail"

        control_scores[control] = {
            "total_rules": total_rules,
            "failed_rules": failed_rules,
            "passed_rules": passed_rules,
            "score": score,
            "status": status,
        }

    return control_scores