MITRE = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
}

def mapping(technique_id: str | None):
    return MITRE.get(technique_id or "", (None, None))
