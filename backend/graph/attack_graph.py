import networkx as nx

def _node(kind,value): return f"{kind}:{value}"
def build_graph(incident, events, detections):
    """Create only relationships that are directly supported by the same event."""
    graph=nx.MultiDiGraph(); graph.add_node(_node("incident",incident.incident_id),type="incident",label=incident.incident_id)
    evidence_ids={d.event_id for d in detections} or {e.event_id for e in events}
    edge_index={}
    def add(kind_a,value_a,kind_b,value_b,relationship,event,confidence=.9):
        if not value_a or not value_b:return
        source,target=_node(kind_a,value_a),_node(kind_b,value_b)
        graph.add_node(source,type=kind_a,label=value_a); graph.add_node(target,type=kind_b,label=value_b)
        key=(source,target,relationship)
        if key in edge_index:
            edge_index[key]["event_ids"].append(event.event_id); return
        data={"relationship":relationship,"timestamp":event.timestamp.isoformat(),"event_ids":[event.event_id],"confidence":confidence,"inferred":False}
        graph.add_edge(source,target,**data); edge_index[key]=data
    for event in events:
        if event.event_id not in evidence_ids:continue
        # Incident association is evidence-backed membership, not an entity-to-entity claim.
        for kind,value in [("host",event.host),("user",event.user),("ip",event.source_ip),("ip",event.destination_ip),("process",event.process_name),("domain",event.domain)]:
            if value:add("incident",incident.incident_id,kind,value,"evidence associated with incident",event)
        add("host",event.host,"user",event.user,"user activity observed on host",event)
        add("host",event.host,"ip",event.source_ip,"host observed using source IP",event)
        add("host",event.host,"process",event.process_name,"process observed on host",event)
        add("process",event.parent_process,"process",event.process_name,"parent process observed spawning process",event)
        add("ip",event.source_ip,"ip",event.destination_ip,"network connection observed",event)
        add("ip",event.source_ip,"domain",event.domain,"source IP observed querying or connecting to domain",event)
        add("process",event.process_name,"domain",event.domain,"process associated with domain activity",event)
    return {"nodes":[{"id":node,**data} for node,data in graph.nodes(data=True)],"edges":[{"id":f"{source}-{target}-{index}","source":source,"target":target,**data} for source,target,index,data in graph.edges(keys=True,data=True)]}

def reachability(graph_data,start=None):
    """Return only observed host/source-IP to destination-IP chains as defensive leads."""
    nodes={node["id"]:node for node in graph_data["nodes"]}; edges=graph_data["edges"]
    starts=[start] if start else [node["id"] for node in graph_data["nodes"] if node.get("type")=="host"]
    links={}
    for edge in edges:
        links.setdefault(edge["source"],[]).append(edge)
    output=[]; seen=set()
    for host in starts:
        for host_ip in links.get(host,[]):
            if host_ip["relationship"]!="host observed using source IP":continue
            for connection in links.get(host_ip["target"],[]):
                if connection["relationship"]!="network connection observed":continue
                key=(host,connection["target"])
                if key in seen:continue
                seen.add(key); output.append({"starting_entity":host,"potential_entity":connection["target"],"relationship":"observed source-IP to destination-IP connection","supporting_event_ids":sorted(set(host_ip["event_ids"]+connection["event_ids"])),"confidence":min(host_ip["confidence"],connection["confidence"]),"reason":"Observed connectivity is an investigation lead only; it does not establish access or compromise."})
    return output
