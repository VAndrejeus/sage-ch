from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class HostExplanation:
    hostname: str
    platform: str
    risk_level: str
    finding_count: int
    top_categories: List[str] = field(default_factory=list)
    top_controls: List[str] = field(default_factory=list)
    key_risk_drivers: List[str] = field(default_factory=list)
    overall_explanation: str = ""
    supporting_findings: List[str] = field(default_factory=list)
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationItem:
    hostname: str
    priority: int
    title: str
    reason: str
    affected_findings: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    controls: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    implementation_notes: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BatchNarrative:
    batch_id: str
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overview: str = ""
    highest_priority_hosts: List[str] = field(default_factory=list)
    top_problem_areas: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)