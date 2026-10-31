from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from datetime import timedelta
from uuid import uuid4
from backend.models import Incident
from backend.risk.scoring import score_values

RANK={"informational":0,"low":1,"medium":2,"high":3,"critical":4}

@dataclass
class IncidentState:
    incident_id: str
    first_observed: object
    last_observed: object
    hosts: set[str]=field(default_factory=set)
    users: set[str]=field(default_factory=set)
    techniques: set[str]=field(default_factory=set)
    tactics: set[str]=field(default_factory=set)
    reasons: set[str]=field(default_factory=set)
    detection_count: int=0
    event_count: int=0
    confidence_total: float=0
    highest_severity: str="informational"
    last_event_id: str | None=None
    active_entities: set[str]=field(default_factory=set)
    def add(self,detection,event,reasons):
        self.first_observed=min(self.first_observed,event.timestamp); self.last_observed=max(self.last_observed,event.timestamp)
        self.hosts.update(value for value in [event.host] if value); self.users.update(value for value in [event.user] if value)
        self.techniques.add(detection.technique_id); self.tactics.add(detection.tactic); self.reasons.update(reasons)
        self.detection_count+=1; self.confidence_total+=detection.confidence
        if RANK.get(detection.severity,0)>RANK.get(self.highest_severity,0): self.highest_severity=detection.severity
    def merge(self,other):
        self.first_observed=min(self.first_observed,other.first_observed); self.last_observed=max(self.last_observed,other.last_observed)
        self.hosts.update(other.hosts); self.users.update(other.users); self.techniques.update(other.techniques); self.tactics.update(other.tactics); self.reasons.update(other.reasons)
        self.detection_count+=other.detection_count; self.event_count+=other.event_count; self.confidence_total+=other.confidence_total
        self.active_entities.update(other.active_entities)
        if RANK.get(other.highest_severity,0)>RANK.get(self.highest_severity,0): self.highest_severity=other.highest_severity
    def model(self):
        confidence=round(self.confidence_total/max(1,self.detection_count),2)
        result=Incident(incident_id=self.incident_id,first_observed=self.first_observed,last_observed=self.last_observed,hosts=sorted(self.hosts),users=sorted(self.users),event_count=self.event_count,detection_count=self.detection_count,techniques=sorted(self.techniques),severity=self.highest_severity,confidence=confidence,correlation_reasons=sorted(self.reasons) or ["Single evidence-backed detection; not linked to unrelated activity"])
        result.risk_score,result.risk_label,result.risk_reasons=score_values(self.highest_severity,self.detection_count,len(self.tactics),confidence)
        return result

class StreamingCorrelator:
    """Bounded-window correlation that stores event membership externally."""
    def __init__(self,window_minutes=60,member_sink=None):
        self.window=timedelta(minutes=window_minutes); self.member_sink=member_sink
        self.states={}; self.entity_index={}; self.expiry=deque(); self._scheduled=set(); self.merges=[]; self.finalized=[]
    @staticmethod
    def entities(event):
        return [("host",event.host),("user",event.user),("source IP",event.source_ip),("destination IP",event.destination_ip),("domain",event.domain)]
    def _expire(self,timestamp):
        cutoff=timestamp-self.window
        while self.expiry and self.expiry[0][0]<cutoff:
            seen,entity=self.expiry.popleft(); self._scheduled.discard(entity); current=self.entity_index.get(entity)
            if current and current[0]<cutoff:
                self.entity_index.pop(entity,None)
                state=self.states.get(current[1])
                if state:
                    state.active_entities.discard(entity)
                    if not state.active_entities:self._finalize(current[1])
            elif current: self.expiry.append((current[0],entity)); self._scheduled.add(entity)

    def _finalize(self,incident_id):
        state=self.states.pop(incident_id,None)
        if state:self.finalized.append(state)

    def drain_finalized(self):
        values=[state.model() for state in self.finalized]
        self.finalized.clear()
        return values

    def finalize_all(self):
        for incident_id in list(self.states):self._finalize(incident_id)
        return self.drain_finalized()

    def _merge(self,source_id,target_id):
        source=self.states.pop(source_id,None); target=self.states.get(target_id)
        if source is None or target is None:return
        target.merge(source); self.merges.append((source_id,target_id))
        for entity,current in self.entity_index.items():
            if current[1]==source_id:self.entity_index[entity]=(current[0],target_id)
    def add(self,detection,event):
        self._expire(event.timestamp); matches=[]; reasons=[]
        for label,value in self.entities(event):
            if not value: continue
            active=self.entity_index.get(f"{label}:{value}")
            if active:
                matches.append(active[1]); reasons.append(f"Shared {label} within {int(self.window.total_seconds()/60)} minutes")
        matches=list(dict.fromkeys(matches))
        incident_id=matches[0] if matches else "INC-"+str(uuid4())[:8].upper()
        for other_id in matches[1:]:self._merge(other_id,incident_id)
        if incident_id not in self.states:self.states[incident_id]=IncidentState(incident_id,event.timestamp,event.timestamp)
        state=self.states[incident_id]; state.add(detection,event,reasons)
        if state.last_event_id!=event.event_id: state.event_count+=1; state.last_event_id=event.event_id
        if self.member_sink:self.member_sink(incident_id,event.event_id)
        for label,value in self.entities(event):
            if value:
                entity=f"{label}:{value}"; self.entity_index[entity]=(event.timestamp,incident_id); state.active_entities.add(entity)
                if entity not in self._scheduled:self.expiry.append((event.timestamp,entity)); self._scheduled.add(entity)
        if not state.active_entities:self._finalize(incident_id)
        return incident_id
    def incidents(self): return [state.model() for state in self.finalized]+[state.model() for state in self.states.values()]

    def export_state(self) -> dict:
        return {
            "entity_index": {
                k: (v[0].isoformat() if hasattr(v[0], "isoformat") else str(v[0]), v[1])
                for k, v in self.entity_index.items()
            },
            "states": {
                k: {
                    "incident_id": v.incident_id,
                    "first_observed": v.first_observed.isoformat() if hasattr(v.first_observed, "isoformat") else str(v.first_observed),
                    "last_observed": v.last_observed.isoformat() if hasattr(v.last_observed, "isoformat") else str(v.last_observed),
                    "hosts": list(v.hosts),
                    "users": list(v.users),
                    "techniques": list(v.techniques),
                    "tactics": list(v.tactics),
                    "reasons": list(v.reasons),
                    "detection_count": v.detection_count,
                    "event_count": v.event_count,
                    "confidence_total": v.confidence_total,
                    "highest_severity": v.highest_severity,
                    "last_event_id": v.last_event_id,
                    "active_entities": list(v.active_entities),
                }
                for k, v in self.states.items()
            },
        }

    def import_state(self, state: dict | None) -> None:
        if not state or not isinstance(state, dict):
            return
        from datetime import datetime
        self.states.clear()
        self.entity_index.clear()
        self.expiry.clear()
        self._scheduled.clear()

        for k, v in state.get("entity_index", {}).items():
            ts = datetime.fromisoformat(v[0])
            self.entity_index[k] = (ts, v[1])
            self.expiry.append((ts, k))
            self._scheduled.add(k)

        for k, v in state.get("states", {}).items():
            istate = IncidentState(
                incident_id=v["incident_id"],
                first_observed=datetime.fromisoformat(v["first_observed"]),
                last_observed=datetime.fromisoformat(v["last_observed"]),
                hosts=set(v.get("hosts", [])),
                users=set(v.get("users", [])),
                techniques=set(v.get("techniques", [])),
                tactics=set(v.get("tactics", [])),
                reasons=set(v.get("reasons", [])),
                detection_count=v.get("detection_count", 0),
                event_count=v.get("event_count", 0),
                confidence_total=v.get("confidence_total", 0.0),
                highest_severity=v.get("highest_severity", "informational"),
                last_event_id=v.get("last_event_id"),
                active_entities=set(v.get("active_entities", [])),
            )
            self.states[k] = istate

def correlate(events,detections,window_minutes=60):
    by_id={event.event_id:event for event in events}; members=[]; correlator=StreamingCorrelator(window_minutes,lambda incident_id,event_id:members.append((incident_id,event_id)))
    for detection in sorted(detections,key=lambda item:by_id[item.event_id].timestamp):
        if detection.event_id in by_id:correlator.add(detection,by_id[detection.event_id])
    results=correlator.incidents()
    for incident in results:incident.evidence_event_ids=sorted(event_id for candidate,event_id in members if candidate==incident.incident_id)
    return results
