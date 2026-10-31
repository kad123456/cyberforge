from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_kind: str = "event"
    category: str = "unknown"
    action: str = "unknown"
    severity: str = "informational"
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    process_name: str | None = None
    process_id: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    registry_path: str | None = None
    domain: str | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)
    rule_context: dict[str, Any] = Field(default_factory=dict, exclude=True)


@dataclass(slots=True)
class NormalizedEventRecord:
    """Lightweight validated-by-parser record used during bulk ingestion."""

    event_id: str
    timestamp: datetime
    event_kind: str = "event"
    category: str = "unknown"
    action: str = "unknown"
    severity: str = "informational"
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    process_name: str | None = None
    process_id: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    registry_path: str | None = None
    domain: str | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None
    raw_event: dict[str, Any] = field(default_factory=dict)
    rule_context: dict[str, Any] = field(default_factory=dict)
    raw_event_json: str | bytes | None = None
    timestamp_us: int = 0

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        value = asdict(self)
        value.pop("rule_context", None)
        value.pop("raw_event_json", None)
        value.pop("timestamp_us", None)
        return value

class Detection(BaseModel):
    detection_id: str
    event_id: str
    rule_id: str
    rule_name: str
    severity: str
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: dict[str, Any]

class Incident(BaseModel):
    incident_id: str
    first_observed: datetime
    last_observed: datetime
    hosts: list[str] = []
    users: list[str] = []
    event_count: int
    detection_count: int
    techniques: list[str] = []
    evidence_event_ids: list[str] = []
    severity: str
    confidence: float
    correlation_reasons: list[str] = []
    risk_score: int = 0
    risk_label: str = "Low"
    risk_reasons: list[str] = []
    attack_type: str = "Suspicious Security Anomaly"
    behavior_summary: str = ""
