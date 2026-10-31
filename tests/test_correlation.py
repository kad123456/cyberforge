from backend.correlation.correlator import correlate
from backend.models import Detection
from tests.test_detection import make

def test_shared_host_correlates():
    a,b=make(),make(); b.event_id="y"; a.host=b.host="WS-01"; b.timestamp=b.timestamp.replace(minute=30)
    d=lambda ident,event:Detection(detection_id=ident,event_id=event.event_id,rule_id="r",rule_name="r",severity="high",technique_id="T1059.001",technique_name="PowerShell",tactic="Execution",confidence=.8,evidence={})
    incidents=correlate([a,b],[d("a",a),d("b",b)])
    assert len(incidents)==1 and incidents[0].detection_count==2
