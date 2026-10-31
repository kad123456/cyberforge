from typing import Iterable

SEVERITY = {"informational": 0, "low": 10, "medium": 25, "high": 45, "critical": 65}

def score_values(highest_severity, detection_count, tactic_count, average_confidence):
    highest = SEVERITY.get(highest_severity, 0)
    volume = min(15, max(0, (detection_count - 1) * 3))
    breadth = min(10, max(0, (tactic_count - 1) * 5))
    confidence = round(average_confidence * 10)
    value = min(100, round(highest + volume + breadth + confidence))
    label = "Critical" if value >= 80 else "High" if value >= 55 else "Medium" if value >= 25 else "Low"
    return value, label, [
        f"highest detection severity contributes {highest}",
        f"{detection_count} detection(s) contribute {volume}",
        f"{tactic_count} tactic(s) contribute {breadth}",
        f"average evidence confidence contributes {confidence}",
    ]

def classify_attack_behavior(
    techniques: Iterable[str],
    tactics: Iterable[str] = (),
    reasons: Iterable[str] = (),
) -> tuple[str, str]:
    """Classify the attack behavior based on observed MITRE techniques, tactics, and evidence.

    Returns (attack_type, behavior_summary).
    """
    tech_set = set(techniques or [])
    tactic_set = {str(t).lower().strip() for t in tactics or []}
    reasons_list = list(reasons or [])

    has_brute_force = "T1110" in tech_set or "credential access" in tactic_set
    has_ransomware = "T1486" in tech_set or "impact" in tactic_set
    has_scripting = "T1059.001" in tech_set or "execution" in tactic_set
    has_persistence = "T1547.001" in tech_set or "persistence" in tactic_set
    has_c2 = "T1071.001" in tech_set or "command and control" in tactic_set
    has_ips_exploit = "T1190" in tech_set
    has_phishing = "T1566" in tech_set or any("phish" in str(r).lower() for r in reasons_list)

    stages = []
    if has_phishing or has_ips_exploit:
        stages.append("Initial Access")
    if has_scripting:
        stages.append("Execution")
    if has_persistence:
        stages.append("Persistence")
    if has_brute_force:
        stages.append("Credential Access")
    if has_c2:
        stages.append("Command & Control")
    if has_ransomware:
        stages.append("Impact")

    if len(stages) >= 3:
        attack_type = "Multi-Stage Attack Campaign (APT)"
        behavior_summary = f"Multi-stage intrusion chain spanning: {' -> '.join(stages)}"
        return attack_type, behavior_summary
    elif len(stages) == 2:
        attack_type = f"Coordinated {' & '.join(stages)} Activity"
        behavior_summary = f"Correlated attack behavior linking {' and '.join(stages)}"
        return attack_type, behavior_summary

    if has_ransomware:
        return "Ransomware / Mass Impact", "Mass file encryption, locking, or destruction activity detected."
    if has_brute_force:
        return "Credential Access / Brute Force", "Repeated automated authentication failures or credential guessing observed."
    if has_scripting:
        return "Malicious Script Execution", "Encoded PowerShell or Office-spawned scripting shells detected."
    if has_persistence:
        return "Host Persistence Mechanism", "Unauthorized startup or registry Run key modification for persistence."
    if has_c2:
        return "Command & Control / Exfiltration", "Outbound beaconing or connection to suspicious external domain."
    if has_ips_exploit:
        return "Exploit Public-Facing Application", "Firewall IPS critical vulnerability exploitation signature blocked or reported."
    if has_phishing:
        return "Phishing / Social Engineering", "Network activity matching known phishing content or web filter category."

    return "Suspicious Security Anomaly", "Unusual activity correlated across entities requiring investigation."

def score(incident, detections):
    highest = max((d.severity for d in detections), key=lambda value: SEVERITY.get(value, 0), default="informational")
    return score_values(highest, len(detections), len({d.tactic for d in detections}), sum(d.confidence for d in detections) / max(1, len(detections)))
