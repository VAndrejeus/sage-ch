from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass(frozen=True)
class AssessmentRule:
    rule_id: str
    title: str
    target_platforms: List[str]
    condition: str
    severity: str
    category: str
    description: str
    expected: str
    recommendation: str
    cis_controls: List[str] = field(default_factory=list)
    enabled: bool = True
    metadata: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


RULES: List[AssessmentRule] = [
    AssessmentRule(
        rule_id="RULE-WIN-001",
        title="Windows update data missing",
        target_platforms=["windows"],
        condition="missing_update_data",
        severity="medium",
        category="patching",
        description="Windows host does not include update assessment data.",
        expected="Windows host should include update assessment data.",
        recommendation="Ensure the Windows agent collects and reports update information.",
        cis_controls=["CIS Control 7"],
    ),
    AssessmentRule(
        rule_id="RULE-WIN-002",
        title="Windows security updates missing",
        target_platforms=["windows"],
        condition="missing_security_updates",
        severity="high",
        category="patching",
        description="Windows host reports missing security updates.",
        expected="Windows host should not have missing security updates.",
        recommendation="Review and apply approved security updates on the endpoint.",
        cis_controls=["CIS Control 7"],
    ),
    AssessmentRule(
        rule_id="RULE-LNX-001",
        title="Linux update data missing",
        target_platforms=["linux"],
        condition="missing_update_data",
        severity="medium",
        category="patching",
        description="Linux host does not include update assessment data.",
        expected="Linux host should include update assessment data.",
        recommendation="Ensure the Linux agent collects and reports update information.",
        cis_controls=["CIS Control 7"],
    ),
    AssessmentRule(
        rule_id="RULE-LNX-002",
        title="Linux security updates missing",
        target_platforms=["linux"],
        condition="missing_security_updates",
        severity="high",
        category="patching",
        description="Linux host reports missing security updates.",
        expected="Linux host should not have missing security updates.",
        recommendation="Review and apply approved security updates on the endpoint.",
        cis_controls=["CIS Control 7"],
    ),
    AssessmentRule(
        rule_id="RULE-COM-001",
        title="Software inventory missing",
        target_platforms=["windows", "linux"],
        condition="missing_software_inventory",
        severity="medium",
        category="inventory",
        description="Host does not include software inventory data.",
        expected="Host should include software inventory data.",
        recommendation="Ensure the agent collects installed software or package inventory.",
        cis_controls=["CIS Control 1", "CIS Control 2"],
    ),
    AssessmentRule(
        rule_id="RULE-COM-002",
        title="Host identity data missing",
        target_platforms=["windows", "linux"],
        condition="missing_host_identity",
        severity="high",
        category="identity",
        description="Host is missing basic identity data such as hostname, OS, or IP.",
        expected="Host should include hostname, OS, and IP information.",
        recommendation="Ensure host identity fields are collected before ingestion.",
        cis_controls=["CIS Control 1"],
    ),
    AssessmentRule(
        rule_id="RULE-COM-003",
        title="UCKG alignment missing",
        target_platforms=["windows", "linux"],
        condition="uckg_alignment_missing",
        severity="low",
        category="alignment",
        description="Host could not be aligned to a UCKG entity.",
        expected="Host should align to a UCKG entity.",
        recommendation="Review normalized host fields and alignment logic.",
        cis_controls=["CIS Control 1"],
        enabled=False,
    ),
    AssessmentRule(
        rule_id="RULE-COM-004",
        title="Too many network interfaces",
        target_platforms=["windows", "linux"],
        condition="excessive_interface_count",
        severity="medium",
        category="network",
        description="Host has an unusually high number of interfaces or IP addresses.",
        expected="Host should have a reasonable number of interfaces.",
        recommendation="Review host network configuration and interface inventory.",
        cis_controls=["CIS Control 1"],
        metadata={"threshold": 10},
    ),
]


def get_all_rules(enabled_only: bool = True) -> List[AssessmentRule]:
    if enabled_only:
        return [rule for rule in RULES if rule.enabled]
    return list(RULES)


def get_rules_for_platform(platform: str, enabled_only: bool = True) -> List[AssessmentRule]:
    normalized_platform = (platform or "").strip().lower()
    rules = get_all_rules(enabled_only=enabled_only)

    if "windows" in normalized_platform:
        platform_family = "windows"
    elif (
        "linux" in normalized_platform
        or "ubuntu" in normalized_platform
        or "debian" in normalized_platform
        or "centos" in normalized_platform
        or "rhel" in normalized_platform
        or "fedora" in normalized_platform
    ):
        platform_family = "linux"
    else:
        platform_family = normalized_platform

    return [
        rule for rule in rules
        if platform_family in [p.lower() for p in rule.target_platforms]
    ]

def get_rule_by_id(rule_id: str) -> Optional[AssessmentRule]:
    if not rule_id:
        return None

    normalized_rule_id = rule_id.strip().upper()
    for rule in RULES:
        if rule.rule_id.upper() == normalized_rule_id:
            return rule
    return None


def get_rules_as_dicts(enabled_only: bool = True) -> List[Dict[str, object]]:
    return [rule.to_dict() for rule in get_all_rules(enabled_only=enabled_only)]