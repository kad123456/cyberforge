SEVERITY={"informational":0,"low":10,"medium":25,"high":45,"critical":65}
def score_values(highest_severity,detection_count,tactic_count,average_confidence):
    highest=SEVERITY.get(highest_severity,0); volume=min(15,max(0,(detection_count-1)*3)); breadth=min(10,max(0,(tactic_count-1)*5)); confidence=round(average_confidence*10)
    value=min(100,round(highest+volume+breadth+confidence)); label="Critical" if value>=80 else "High" if value>=55 else "Medium" if value>=25 else "Low"
    return value,label,[f"highest detection severity contributes {highest}",f"{detection_count} detection(s) contribute {volume}",f"{tactic_count} tactic(s) contribute {breadth}",f"average evidence confidence contributes {confidence}"]
def score(incident,detections):
    highest=max((d.severity for d in detections),key=lambda value:SEVERITY.get(value,0),default="informational")
    return score_values(highest,len(detections),len({d.tactic for d in detections}),sum(d.confidence for d in detections)/max(1,len(detections)))
