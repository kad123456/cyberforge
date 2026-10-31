from backend.graph.attack_graph import build_graph, reachability
from backend.models import Incident
from tests.test_detection import make

def test_graph_contains_observed_host_edge():
    e=make();e.host="WS-01"; i=Incident(incident_id="INC-1",first_observed=e.timestamp,last_observed=e.timestamp,event_count=1,detection_count=1,severity="high",confidence=.8)
    graph=build_graph(i,[e],[])
    assert any(n["type"]=="host" for n in graph["nodes"])
    assert all(not edge["inferred"] for edge in graph["edges"])

def test_graph_only_adds_supported_network_relationships():
    e=make();e.host="WS-01";e.source_ip="10.0.0.1";e.destination_ip="10.0.0.2"
    i=Incident(incident_id="INC-2",first_observed=e.timestamp,last_observed=e.timestamp,event_count=1,detection_count=1,severity="high",confidence=.8)
    graph=build_graph(i,[e],[])
    assert any(edge["relationship"]=="network connection observed" for edge in graph["edges"])
    assert not any(edge["relationship"]=="observed in event" for edge in graph["edges"])
