from backend.detection.engine import DetectionEngine
from backend.ingestion.parser import normalize

def event(event_id, minute):
    return normalize({"@timestamp":f"2026-01-01T00:{minute:02}:00Z","event":{"id":event_id,"category":["authentication"],"outcome":"failure"},"host":{"name":"SRV-01"},"user":{"name":"admin"}})

def test_authentication_threshold_survives_batch_boundary():
    engine=DetectionEngine()
    assert not engine.detect_batch([event(str(number),number) for number in range(4)])
    detections=engine.detect_batch([event("five",4)])
    assert any(detection.rule_id=="CS-AUTH-001" for detection in detections)
