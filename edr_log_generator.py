#!/usr/bin/env python3
"""
EDR Log Generator - synthetic endpoint telemetry for SIEM testing.

Produces the kinds of events a SIEM normally ingests from an EDR
(process, network, file, registry, DNS, authentication), mixed with a
small fraction of events pre-tagged as suspicious with MITRE ATT&CK
technique IDs and rule names. It is a DATA generator for exercising SIEM
parsers, dashboards, correlation rules and alert pipelines - the
"attack" records carry detection metadata and sanitized representative
fields, not runnable commands.

Ships events as ECS JSON or CEF to: stdout, a file (NDJSON), syslog
(UDP/TCP) or an HTTP endpoint (Splunk HEC / Elastic / generic).

Pure standard library - no pip installs required.

Examples:
  python edr_log_generator.py --count 20
  python edr_log_generator.py --format cef --output syslog --host 10.0.0.50 --port 514 --rate 5 --alert-ratio 0.1
  python edr_log_generator.py --count 10000 --output file --file edr_events.json --rate 0
  python edr_log_generator.py --output http --url https://splunk:8088/services/collector/event --token <HEC> --hec --insecure
  python edr_log_generator.py --output http --url http://elastic:9200/edr-logs/_doc --basic-auth elastic:changeme
"""

import argparse
import base64
import hashlib
import json
import random
import socket
import ssl
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Environment model (edit to match your lab / demo)
# --------------------------------------------------------------------------
DOMAIN = "CORP"
VENDOR, PRODUCT, VERSION = "Mitigata", "SimEDR", "1.0"

HOSTS = [
    {"name": f"WS-{dept}-{i:03d}", "ip": f"10.10.{n}.{i}", "os": "windows",
     "os_ver": "Windows 11 Enterprise 23H2"}
    for n, dept in enumerate(["FIN", "HR", "ENG", "SALES"], start=1)
    for i in range(10, 16)
] + [
    {"name": "SRV-DC-01", "ip": "10.10.0.10", "os": "windows", "os_ver": "Windows Server 2022"},
    {"name": "SRV-FILE-01", "ip": "10.10.0.20", "os": "windows", "os_ver": "Windows Server 2022"},
    {"name": "SRV-WEB-01", "ip": "10.10.0.30", "os": "linux", "os_ver": "Ubuntu 22.04 LTS"},
    {"name": "SRV-DB-01", "ip": "10.10.0.40", "os": "linux", "os_ver": "RHEL 9.3"},
]
USERS = ["rkumar", "asharma", "pmehta", "sgupta", "nverma", "kiyer", "dnair",
         "vreddy", "jdsouza", "mkhan", "svc_backup", "svc_sql"]

BENIGN_WIN_PROCS = [
    ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "explorer.exe"),
    ("msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "explorer.exe"),
    ("outlook.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "explorer.exe"),
    ("winword.exe", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "explorer.exe"),
    ("excel.exe", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "explorer.exe"),
    ("teams.exe", r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe", "explorer.exe"),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe", "services.exe"),
    ("notepad.exe", r"C:\Windows\System32\notepad.exe", "explorer.exe"),
    ("OneDrive.exe", r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "explorer.exe"),
    ("MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe", "services.exe"),
]
BENIGN_LINUX_PROCS = [
    ("sshd", "/usr/sbin/sshd", "systemd"), ("nginx", "/usr/sbin/nginx", "systemd"),
    ("cron", "/usr/sbin/cron", "systemd"), ("python3", "/usr/bin/python3", "bash"),
    ("postgres", "/usr/lib/postgresql/14/bin/postgres", "systemd"),
]
BENIGN_DOMAINS = ["login.microsoftonline.com", "outlook.office365.com", "www.google.com",
                  "teams.microsoft.com", "github.com", "update.microsoft.com",
                  "slack.com", "s3.amazonaws.com", "zoom.us"]
# Reserved documentation ranges / clearly-fake names, so nothing resolves to a real host.
SUSPECT_DOMAINS = ["suspicious-example-c2.invalid", "bad-domain-demo.test", "sim-exfil.example"]
SUSPECT_IPS = ["198.51.100.23", "203.0.113.57", "192.0.2.88"]   # TEST-NET ranges (RFC 5737)

SEVERITY_NUM = {"informational": 0, "low": 3, "medium": 5, "high": 8, "critical": 10}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def fake_hash(seed):
    return {"md5": hashlib.md5(seed.encode()).hexdigest(),
            "sha1": hashlib.sha1(seed.encode()).hexdigest(),
            "sha256": hashlib.sha256(seed.encode()).hexdigest()}


def rand_pid():
    return random.randint(1000, 65000)


def public_ip():
    return f"{random.choice([13, 20, 40, 52, 104, 142])}.{random.randint(0,255)}." \
           f"{random.randint(0,255)}.{random.randint(1,254)}"


def base_event(host, user, category, etype, action, severity="informational"):
    return {
        "@timestamp": now_iso(),
        "event": {"id": str(uuid.uuid4()),
                  "kind": "alert" if severity != "informational" else "event",
                  "category": [category], "type": [etype], "action": action,
                  "severity": SEVERITY_NUM[severity], "module": "edr",
                  "dataset": f"edr.{category}"},
        "agent": {"id": hashlib.md5(host["name"].encode()).hexdigest()[:16],
                  "type": "edr", "name": PRODUCT, "version": VERSION},
        "observer": {"vendor": VENDOR, "product": PRODUCT, "version": VERSION},
        "host": {"name": host["name"], "hostname": host["name"], "ip": [host["ip"]],
                 "os": {"type": host["os"], "full": host["os_ver"]}},
        "user": {"name": user, "domain": DOMAIN},
    }


def proc_block(name, path, cmd, parent_name, parent_pid=None, pid=None):
    return {"pid": pid or rand_pid(), "name": name, "executable": path,
            "command_line": cmd, "hash": fake_hash(path),
            "parent": {"pid": parent_pid or rand_pid(), "name": parent_name},
            "entity_id": str(uuid.uuid4())}


def tag_alert(ev, tid, tname, tactic, rule_name, severity):
    ev["event"]["kind"] = "alert"
    ev["event"]["severity"] = SEVERITY_NUM[severity]
    ev["threat"] = {"framework": "MITRE ATT&CK",
                    "technique": {"id": [tid], "name": [tname]},
                    "tactic": {"name": [tactic]}}
    ev["rule"] = {"id": hashlib.md5(rule_name.encode()).hexdigest()[:8],
                  "name": rule_name, "severity": severity}
    ev["labels"] = {"synthetic": "true", "simulated_detection": "true"}
    return ev


# --------------------------------------------------------------------------
# Benign (normal baseline) events
# --------------------------------------------------------------------------
def benign_process(host, user):
    if host["os"] == "linux":
        name, path, parent = random.choice(BENIGN_LINUX_PROCS)
        cmd = f"{path} {random.choice(['', '-D', '--version'])}".strip()
    else:
        name, path, parent = random.choice(BENIGN_WIN_PROCS)
        path = path.format(u=user)
        cmd = f'"{path}"' + random.choice(["", " --type=renderer", " /safe", " -k netsvcs"])
    ev = base_event(host, user, "process", "start", "process_created")
    ev["process"] = proc_block(name, path, cmd, parent)
    return ev


def benign_network(host, user):
    ev = base_event(host, user, "network", "connection", "network_connection")
    ev["process"] = {"pid": rand_pid(), "name": "chrome.exe" if host["os"] == "windows" else "curl"}
    ev["source"] = {"ip": host["ip"], "port": random.randint(49152, 65535)}
    ev["destination"] = {"ip": public_ip(), "port": random.choice([443, 443, 443, 80]),
                         "domain": random.choice(BENIGN_DOMAINS)}
    ev["network"] = {"transport": "tcp", "direction": "outbound", "protocol": "https",
                     "bytes": random.randint(500, 900000)}
    return ev


def benign_dns(host, user):
    ev = base_event(host, user, "network", "protocol", "dns_query")
    ev["dns"] = {"question": {"name": random.choice(BENIGN_DOMAINS), "type": "A"},
                 "response_code": "NOERROR", "resolved_ip": [public_ip()]}
    ev["process"] = {"pid": rand_pid(),
                     "name": "svchost.exe" if host["os"] == "windows" else "systemd-resolved"}
    return ev


def benign_file(host, user):
    if host["os"] == "windows":
        path = random.choice([
            rf"C:\Users\{user}\Documents\Q3_Report_{random.randint(1,9)}.xlsx",
            rf"C:\Users\{user}\Downloads\meeting_notes.docx",
            rf"C:\Users\{user}\AppData\Local\Temp\tmp{random.randint(1000,9999)}.tmp"])
        proc = random.choice(["excel.exe", "winword.exe", "explorer.exe"])
    else:
        path = random.choice(["/var/log/nginx/access.log", f"/home/{user}/app.py"])
        proc = random.choice(["nginx", "python3", "vim"])
    ev = base_event(host, user, "file", random.choice(["creation", "change"]), "file_modified")
    ev["file"] = {"path": path, "name": path.replace("\\", "/").split("/")[-1],
                  "size": random.randint(100, 5_000_000)}
    ev["process"] = {"pid": rand_pid(), "name": proc}
    return ev


def benign_auth(host, user):
    ev = base_event(host, user, "authentication", "start", "user_logon")
    ev["event"]["outcome"] = random.choices(["success", "failure"], [0.93, 0.07])[0]
    ev["winlog"] = {"event_id": 4624 if ev["event"]["outcome"] == "success" else 4625,
                    "logon": {"type": random.choice(["Interactive", "Network", "RemoteInteractive"])}}
    ev["source"] = {"ip": random.choice(HOSTS)["ip"]}
    return ev


def benign_registry(host, user):
    if host["os"] != "windows":
        return benign_file(host, user)
    ev = base_event(host, user, "registry", "change", "registry_value_set")
    ev["registry"] = {"path": random.choice([
        r"HKCU\Software\Microsoft\Office\16.0\Common\General\RecentFiles",
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\AVSignatureVersion"]),
        "data": {"strings": [str(random.randint(1, 99999))]}}
    ev["process"] = {"pid": rand_pid(), "name": random.choice(["chrome.exe", "MsMpEng.exe"])}
    return ev


BENIGN = [(benign_process, 30), (benign_network, 25), (benign_dns, 20),
          (benign_file, 12), (benign_auth, 8), (benign_registry, 5)]


def gen_benign():
    host, user = random.choice(HOSTS), random.choice(USERS)
    fn = random.choices([g for g, _ in BENIGN], [w for _, w in BENIGN])[0]
    return fn(host, user)


# --------------------------------------------------------------------------
# Alert-tagged events (detection metadata only; fields are representative,
# not operational). These exist so your SIEM has something to alert on.
# --------------------------------------------------------------------------
def alert_suspicious_child():
    """Office app spawning a scripting engine - classic detection trigger."""
    host = random.choice([h for h in HOSTS if h["name"].startswith("WS-")])
    user = random.choice(USERS[:10])
    ev = base_event(host, user, "process", "start", "process_created")
    ev["process"] = proc_block(
        "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -nop -w hidden -enc <REDACTED_BASE64>", "winword.exe")
    return tag_alert(ev, "T1059.001", "PowerShell", "Execution",
                     "Office application spawned a scripting engine", "high")


def alert_c2_beacon():
    host = random.choice([h for h in HOSTS if h["name"].startswith("WS-")])
    user = random.choice(USERS[:10])
    ev = base_event(host, user, "network", "connection", "network_connection")
    ev["process"] = {"pid": rand_pid(), "name": "powershell.exe"}
    ev["source"] = {"ip": host["ip"], "port": random.randint(49152, 65535)}
    ev["destination"] = {"ip": random.choice(SUSPECT_IPS), "port": 443,
                         "domain": random.choice(SUSPECT_DOMAINS)}
    ev["network"] = {"transport": "tcp", "direction": "outbound", "bytes": random.randint(1000, 5000)}
    return tag_alert(ev, "T1071.001", "Web Protocols", "Command and Control",
                     "Beaconing to low-reputation destination", "high")


def alert_bruteforce():
    host = next(h for h in HOSTS if h["name"] == "SRV-DC-01")
    user = random.choice(USERS)
    ev = base_event(host, user, "authentication", "start", "user_logon")
    ev["event"]["outcome"] = "failure"
    ev["winlog"] = {"event_id": 4625, "logon": {"type": "Network"}}
    ev["source"] = {"ip": random.choice(SUSPECT_IPS)}
    ev["labels_extra"] = {"failed_count_5min": random.randint(25, 120)}
    return tag_alert(ev, "T1110", "Brute Force", "Credential Access",
                     "High rate of failed logons from single source", "medium")


def alert_persistence_runkey():
    host = random.choice([h for h in HOSTS if h["name"].startswith("WS-")])
    user = random.choice(USERS[:10])
    ev = base_event(host, user, "registry", "change", "registry_value_set")
    ev["registry"] = {"path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<SUSPECT_ENTRY>",
                      "data": {"strings": [r"%AppData%\<redacted>.exe"]}}
    ev["process"] = {"pid": rand_pid(), "name": "powershell.exe"}
    return tag_alert(ev, "T1547.001", "Registry Run Keys / Startup Folder", "Persistence",
                     "Autorun key created by scripting engine", "high")


def alert_mass_file_change():
    """Ransomware-style rapid rename burst - counts only, no payload."""
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    ev = base_event(host, user, "file", "change", "file_rename")
    ev["file"] = {"path": rf"C:\Users\{user}\Documents\<many>.locked" if host["os"] == "windows"
                  else f"/home/{user}/<many>.locked", "extension": "locked"}
    ev["labels_extra"] = {"files_renamed_60s": random.randint(200, 4000)}
    ev["process"] = {"pid": rand_pid(), "name": "unknown.exe"}
    return tag_alert(ev, "T1486", "Data Encrypted for Impact", "Impact",
                     "Rapid mass file rename to uniform extension", "critical")


ALERTS = [alert_suspicious_child, alert_c2_beacon, alert_bruteforce,
          alert_persistence_runkey, alert_mass_file_change]


def gen_alert():
    return random.choice(ALERTS)()


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------
def to_json(ev):
    return json.dumps(ev, separators=(",", ":"))


def _cef_escape(v):
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_cef(ev):
    sev = ev["event"]["severity"]
    name = ev.get("rule", {}).get("name", ev["event"]["action"])
    sig = ev.get("rule", {}).get("id", ev["event"]["type"][0])
    hdr = f"CEF:0|{VENDOR}|{PRODUCT}|{VERSION}|{sig}|{name}|{sev}|"
    ext = {
        "rt": ev["@timestamp"], "dvchost": ev["host"]["name"],
        "suser": ev["user"]["name"], "cat": ev["event"]["category"][0],
        "act": ev["event"]["action"], "externalId": ev["event"]["id"],
    }
    if "process" in ev:
        ext["dproc"] = ev["process"].get("name", "")
        if ev["process"].get("command_line"):
            ext["cs1Label"], ext["cs1"] = "cmdline", ev["process"]["command_line"]
    if "destination" in ev:
        ext["dst"] = ev["destination"].get("ip", "")
        ext["dpt"] = ev["destination"].get("port", "")
        if ev["destination"].get("domain"):
            ext["destinationDnsDomain"] = ev["destination"]["domain"]
    if "source" in ev:
        ext["src"] = ev["source"].get("ip", "")
    if "threat" in ev:
        ext["cs2Label"], ext["cs2"] = "mitre", ",".join(ev["threat"]["technique"]["id"])
    body = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items() if v != "")
    return hdr + body


def render(ev, fmt):
    return to_cef(ev) if fmt == "cef" else to_json(ev)


# --------------------------------------------------------------------------
# Output sinks
# --------------------------------------------------------------------------
class StdoutSink:
    def send(self, line): print(line, flush=True)
    def close(self): pass


class FileSink:
    def __init__(self, path): self.f = open(path, "a", encoding="utf-8")
    def send(self, line): self.f.write(line + "\n")
    def close(self): self.f.close()


class SyslogSink:
    """RFC3164-ish syslog framing over UDP or TCP."""
    def __init__(self, host, port, protocol):
        self.host, self.port, self.proto = host, port, protocol
        if protocol == "tcp":
            self.sock = socket.create_connection((host, port), timeout=5)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _frame(self, line):
        pri = 134  # facility=local0(16), severity=info(6)
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        host = socket.gethostname()
        return f"<{pri}>{ts} {host} {PRODUCT}: {line}"

    def send(self, line):
        data = self._frame(line).encode("utf-8", "replace")
        if self.proto == "tcp":
            self.sock.sendall(data + b"\n")
        else:
            self.sock.sendto(data, (self.host, self.port))

    def close(self):
        try: self.sock.close()
        except Exception: pass


class HttpSink:
    """Splunk HEC (--hec), Elastic, or any JSON endpoint. One POST per event."""
    def __init__(self, url, token=None, basic_auth=None, hec=False, insecure=False):
        self.url, self.token, self.hec = url, token, hec
        self.headers = {"Content-Type": "application/json"}
        if token and not hec:
            self.headers["Authorization"] = f"Bearer {token}"
        if hec and token:
            self.headers["Authorization"] = f"Splunk {token}"
        if basic_auth:
            self.headers["Authorization"] = "Basic " + base64.b64encode(basic_auth.encode()).decode()
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def send(self, line):
        payload = json.dumps({"event": json.loads(line), "sourcetype": "edr"}) if self.hec else line
        req = urllib.request.Request(self.url, data=payload.encode("utf-8"),
                                     headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=10) as r:
                r.read()
        except Exception as e:
            print(f"[http] send failed: {e}", file=sys.stderr)

    def close(self): pass


def build_sink(a):
    if a.output == "stdout": return StdoutSink()
    if a.output == "file": return FileSink(a.file)
    if a.output == "syslog": return SyslogSink(a.host, a.port, a.protocol)
    if a.output == "http":
        if not a.url: sys.exit("--url is required for --output http")
        return HttpSink(a.url, a.token, a.basic_auth, a.hec, a.insecure)
    sys.exit(f"unknown output {a.output}")


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Synthetic EDR telemetry generator for SIEM testing.")
    p.add_argument("--count", type=int, default=50, help="events to emit (0 = run forever)")
    p.add_argument("--rate", type=float, default=2.0, help="events/sec (0 = as fast as possible)")
    p.add_argument("--alert-ratio", type=float, default=0.05,
                   help="fraction of events tagged as suspicious (0-1)")
    p.add_argument("--format", choices=["json", "cef"], default="json")
    p.add_argument("--output", choices=["stdout", "file", "syslog", "http"], default="stdout")
    p.add_argument("--file", default="edr_events.json")
    p.add_argument("--host", default="127.0.0.1", help="syslog host")
    p.add_argument("--port", type=int, default=514, help="syslog port")
    p.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    p.add_argument("--url", help="HTTP endpoint URL")
    p.add_argument("--token", help="bearer / HEC token")
    p.add_argument("--hec", action="store_true", help="wrap events for Splunk HEC")
    p.add_argument("--basic-auth", help="user:pass for HTTP basic auth")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--seed", type=int, help="RNG seed for reproducible runs")
    a = p.parse_args()

    if a.seed is not None:
        random.seed(a.seed)
    sink = build_sink(a)
    delay = 1.0 / a.rate if a.rate > 0 else 0
    emitted = alerts = 0
    try:
        while a.count == 0 or emitted < a.count:
            ev = gen_alert() if random.random() < a.alert_ratio else gen_benign()
            if ev.get("event", {}).get("kind") == "alert":
                alerts += 1
            sink.send(render(ev, a.format))
            emitted += 1
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        print("\n[stopped]", file=sys.stderr)
    finally:
        sink.close()
    print(f"[done] emitted={emitted} alerts={alerts}", file=sys.stderr)


if __name__ == "__main__":
    main()

