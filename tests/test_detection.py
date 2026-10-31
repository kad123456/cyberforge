from backend.detection.engine import DetectionEngine
from backend.ingestion.parser import normalize

def make(process="powershell.exe", parent="winword.exe", command="powershell -enc demo"):
    return normalize({"@timestamp":"2026-01-01T00:00:00Z","event":{"id":"x","category":["process"]},"process":{"name":process,"parent":{"name":parent},"command_line":command}})

def test_office_child_detection():
    detections=DetectionEngine().detect([make()])
    assert any(x.rule_id=="CS-OFFICE-001" for x in detections)

def test_benign_powershell_without_context_is_not_auto_alerted():
    detections=DetectionEngine().detect([make(parent="explorer.exe",command="powershell Get-Date")])
    assert not detections


def test_detection_ids_are_stable_for_same_event_and_rule():
    engine = DetectionEngine()
    event = make()

    first = engine.detect([event])
    second = engine.detect([event])

    assert {(item.event_id, item.rule_id, item.detection_id) for item in first} == {
        (item.event_id, item.rule_id, item.detection_id) for item in second
    }
