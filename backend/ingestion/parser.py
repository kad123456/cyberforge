from __future__ import annotations
import re, hashlib
from datetime import datetime, timezone
from uuid import uuid4
from typing import Any

import orjson
from backend.models import NormalizedEventRecord
from backend.mitre import mapping

CEF_PREFIX = re.compile(r"^CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|(?P<signature>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)$")
CEF_EXTENSION = re.compile(r"(?P<key>[A-Za-z][A-Za-z0-9]*)(?:=)(?P<value>.*?)(?=\s+[A-Za-z][A-Za-z0-9]*=|$)")
FORTI_PAIR = re.compile(r'(?P<key>[A-Za-z][A-Za-z0-9_]*)=(?:"(?P<quoted>[^"]*)"|(?P<plain>[^\s]+))')

def detect_format(sample: str | bytes) -> str:
    stripped = sample.lstrip()
    if isinstance(stripped, bytes):
        if stripped.startswith(b"CEF:"): return "cef"
        if stripped.startswith(b"{"): return "jsonl"
        if b"date=" in stripped and b"type=" in stripped: return "fortigate"
        return "jsonl"
    if stripped.startswith("CEF:"): return "cef"
    if stripped.startswith("{"): return "jsonl"
    if "date=" in stripped and "type=" in stripped: return "fortigate"
    return "jsonl"

def parse_line(line: str | bytes, source_format: str | None = None) -> dict[str, Any]:
    fmt = source_format or detect_format(line)
    if fmt == "jsonl":
        loaded = orjson.loads(line)
        return loaded.get("event", loaded) if isinstance(loaded.get("event"), dict) and "sourcetype" in loaded else loaded
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    if fmt == "fortigate":
        values={match.group("key"): match.group("quoted") if match.group("quoted") is not None else match.group("plain") for match in FORTI_PAIR.finditer(line)}
        if not values or "date" not in values: raise ValueError("invalid FortiGate key/value record")
        values["_format"]="fortigate"
        return values
    match = CEF_PREFIX.match(line.strip())
    if not match: raise ValueError("invalid CEF record")
    value = match.groupdict(); ext = {m.group("key"): m.group("value") for m in CEF_EXTENSION.finditer(value.pop("extension"))}
    value["extension"] = ext
    return value

def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _event_model(**values):
    """Build an already-normalized event without repeating Pydantic validation."""
    timestamp = values.get("timestamp")
    if not isinstance(timestamp, datetime):
        if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
            timestamp = datetime.fromtimestamp(timestamp, timezone.utc)
        elif isinstance(timestamp, str):
            stamp = timestamp.strip()
            timestamp = datetime.fromisoformat(stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp)
        else:
            raise ValueError("timestamp must be an ISO date/time or Unix timestamp")
    values["timestamp"] = timestamp
    values["timestamp_us"] = int(timestamp.timestamp() * 1_000_000)
    values["event_id"] = str(values.get("event_id") or uuid4())
    for field in (
        "event_kind", "category", "action", "severity", "host", "source_ip", "destination_ip",
        "user", "process_name", "process_id", "parent_process", "command_line", "file_path",
        "registry_path", "domain", "technique_id", "technique_name", "tactic",
    ):
        if values.get(field) is not None:
            values[field] = str(values[field])
    values.setdefault("raw_event", {})
    values.setdefault("rule_context", {})
    return NormalizedEventRecord(**values)

def _rule_context(raw: dict[str, Any], fields=None) -> dict[str, Any]:
    event = raw.get("event", {})
    context = {}
    if isinstance(event, dict) and event.get("outcome") is not None:
        context["outcome"] = event["outcome"]
    if raw.get("status") is not None:
        context["status"] = raw["status"]
    selected = set(fields if fields is not None else ("catdesc",))
    for key in selected:
        value = raw.get(key)
        if value is not None and not isinstance(value, (dict, list)):
            context[key] = value
    return context


def normalize(raw: dict[str, Any], *, raw_context_fields=None):
    if raw.get("_format") == "csv":
        return normalize_csv(raw["record"], raw_context_fields=raw_context_fields)
    if raw.get("_format") == "fortigate":
        return normalize_fortigate(raw)
    if "extension" in raw and "vendor" in raw:
        x = raw["extension"]; tid = (x.get("cs2") or "").split(",")[0] or None
        technique_name, tactic = mapping(tid)
        stamp = x.get("rt") or datetime.now(timezone.utc).isoformat()
        return _event_model(event_id=x.get("externalId") or str(uuid4()), timestamp=stamp, event_kind="alert" if raw.get("severity") not in ("0", "") else "event", category=x.get("cat", "unknown"), action=x.get("act", raw.get("name", "unknown")), severity=str(raw.get("severity", "informational")), host=x.get("dvchost"), user=x.get("suser"), source_ip=x.get("src"), destination_ip=x.get("dst"), process_name=x.get("dproc"), command_line=x.get("cs1") if x.get("cs1Label") == "cmdline" else None, technique_id=tid, technique_name=technique_name, tactic=tactic, raw_event=raw, rule_context=_rule_context(raw, raw_context_fields))
    event = _mapping(raw.get("event")); host = _mapping(raw.get("host")); user = _mapping(raw.get("user")); proc = _mapping(raw.get("process")); net = _mapping(raw.get("network")); threat = _mapping(raw.get("threat"))
    technique = _mapping(threat.get("technique"))
    techs = technique.get("id", [])
    tid = techs[0] if isinstance(techs, list) and techs else (techs if isinstance(techs, str) else None)
    tname, tactic = mapping(tid)
    timestamp = raw.get("@timestamp") or raw.get("timestamp") or datetime.now(timezone.utc).isoformat()
    category = event.get("category", raw.get("category", raw.get("event_type", "unknown"))); category = category[0] if isinstance(category, list) and category else category
    sev = event.get("severity", raw.get("severity", "informational")); sev = {1:"low",2:"low",3:"medium",4:"medium",5:"high",6:"high",7:"high",8:"critical",9:"critical",10:"critical"}.get(sev, str(sev).lower()) if isinstance(sev, int) else str(sev).lower()
    dns = _mapping(raw.get("dns")); question = _mapping(dns.get("question")); destination = _mapping(raw.get("destination")); source = _mapping(raw.get("source"))
    file = _mapping(raw.get("file")); registry = _mapping(raw.get("registry")); parent = proc.get("parent")
    parent_name = _mapping(parent).get("name") if isinstance(parent, dict) else parent
    domain = question.get("name") or destination.get("domain") or raw.get("domain")
    return _event_model(event_id=_text(event.get("id") or raw.get("event_id") or uuid4()), timestamp=timestamp, event_kind=event.get("kind", raw.get("event_kind", raw.get("event_type", "event"))), category=_text(category) or "unknown", action=_text(event.get("action") or raw.get("action")) or "unknown", severity=sev, host=_text(host.get("name") or raw.get("host")), source_ip=_text(source.get("ip") or raw.get("source_ip") or net.get("source_ip")), destination_ip=_text(destination.get("ip") or raw.get("destination_ip") or net.get("destination_ip")), user=_text(user.get("name") or raw.get("user")), process_name=_text(proc.get("name") or raw.get("process_name")), process_id=_text(proc.get("pid") or raw.get("process_id")), parent_process=_text(parent_name or raw.get("parent_process")), command_line=_text(proc.get("command_line") or raw.get("command_line")), file_path=_text(file.get("path") or raw.get("file_path")), registry_path=_text(registry.get("path") or raw.get("registry_path")), domain=_text(domain), technique_id=tid, technique_name=tname, tactic=tactic, raw_event=raw, rule_context=_rule_context(raw, raw_context_fields))


def normalize_csv(record: dict[str, Any], *, raw_context_fields=None):
    """Map common flat security-log column names while retaining every CSV field.

    Unknown columns remain available in ``raw_event``. Organizer-specific
    schemas still need an explicit mapping once their sample is available.
    """
    values = {
        str(key).strip().lower().replace(" ", "_"): (str(value).strip() if value is not None else "")
        for key, value in record.items()
    }

    def get(*names: str) -> str | None:
        for name in names:
            value = values.get(name)
            if value:
                return value
        return None

    category = get("event.category", "event_category", "category", "event_type", "type")
    severity = get("event.severity", "severity", "level", "priority")
    if severity and severity.isdigit():
        severity_value: Any = int(severity)
    else:
        severity_value = severity
    event = {
        "id": get("event.id", "event_id", "record_id", "alert_id", "id"),
        "kind": get("event.kind", "event_kind") or "event",
        "category": [category] if category else [],
        "action": get("event.action", "action", "activity", "operation"),
        "outcome": get("event.outcome", "outcome", "status", "result"),
        "severity": severity_value,
    }
    host_name = get("host.name", "hostname", "computer", "computer_name", "device_name", "host")
    user_name = get("user.name", "username", "account_name", "account", "user")
    source_ip = get("source.ip", "source_ip", "src_ip", "srcip", "client_ip")
    destination_ip = get("destination.ip", "destination_ip", "dst_ip", "dstip", "server_ip")
    process_name = get("process.name", "process_name", "image_name", "imagename", "process")
    parent = get("process.parent.name", "parent_process", "parent_process_name", "parent_image")
    technique_id = get("threat.technique.id", "technique_id", "mitre_technique_id")
    mapped = {
        "@timestamp": get("@timestamp", "timestamp", "event_time", "datetime", "time_created", "date_time"),
        "event": event,
        "host": {"name": host_name} if host_name else {},
        "user": {"name": user_name} if user_name else {},
        "source": {"ip": source_ip} if source_ip else {},
        "destination": {
            **({"ip": destination_ip} if destination_ip else {}),
            **({"domain": get("destination.domain", "dns.question.name", "domain", "fqdn")} if get("destination.domain", "dns.question.name", "domain", "fqdn") else {}),
        },
        "process": {
            **({"name": process_name} if process_name else {}),
            **({"pid": get("process.pid", "process_id", "pid")} if get("process.pid", "process_id", "pid") else {}),
            **({"command_line": get("process.command_line", "command_line", "cmdline", "command")} if get("process.command_line", "command_line", "cmdline", "command") else {}),
            **({"parent": {"name": parent}} if parent else {}),
        },
        "file": {"path": get("file.path", "file_path", "filepath", "filename")} if get("file.path", "file_path", "filepath", "filename") else {},
        "registry": {"path": get("registry.path", "registry_path", "key_path")} if get("registry.path", "registry_path", "key_path") else {},
        "threat": {"technique": {"id": [technique_id]}} if technique_id else {},
        "action": get("action", "event.action"),
        "event_id": event["id"],
        "_csv_record": record,
    }
    result = normalize(mapped)
    result.raw_event = record
    selected = set(raw_context_fields if raw_context_fields is not None else record.keys())
    result.rule_context = _rule_context(record, selected)
    return result

FORTI_SEVERITY = {
    "emergency": "critical", "alert": "critical", "critical": "critical",
    "error": "high", "warning": "medium", "notice": "low",
    "information": "informational", "debug": "informational"
}

def normalize_fortigate_line(line: str | bytes) -> NormalizedEventRecord:
    """Fast single-pass parser and normalizer for raw FortiGate log lines."""
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    fields = {
        m.group("key"): m.group("quoted") if m.group("quoted") is not None else m.group("plain")
        for m in FORTI_PAIR.finditer(line)
    }
    if not fields or "date" not in fields:
        raise ValueError("invalid FortiGate key/value record")
    return _fortigate_fields_to_record(fields)

def normalize_fortigate(raw: dict[str, Any]) -> NormalizedEventRecord:
    """Map FortiGate's space-delimited key/value export without losing fields."""
    return _fortigate_fields_to_record(raw)

def _fortigate_fields_to_record(raw: dict[str, Any]) -> NormalizedEventRecord:
    etime = raw.get("eventtime")
    if etime and str(etime).isdigit():
        ts_us = int(etime) // 1000
        timestamp = datetime.fromtimestamp(ts_us / 1_000_000, timezone.utc)
    else:
        date, clock, tz = raw.get("date"), raw.get("time"), raw.get("tz", "+0000")
        try:
            timestamp = datetime.fromisoformat(f"{date}T{clock}{tz}")
        except (TypeError, ValueError):
            timestamp = datetime.now(timezone.utc)
        ts_us = int(timestamp.timestamp() * 1_000_000)

    type_name, subtype = raw.get("type", ""), raw.get("subtype", "")
    status = raw.get("status", "")
    if type_name == "event" and status in {"failed", "success"}:
        category = "authentication"
    elif subtype == "ips":
        category = "intrusion"
    elif subtype == "virus":
        category = "malware"
    elif type_name in {"traffic", "utm"}:
        category = "network"
    else:
        category = type_name or "unknown"

    severity = FORTI_SEVERITY.get(str(raw.get("level", "information")).lower(), "informational")
    action = raw.get("action", "unknown")
    event_kind = "alert" if severity in {"high", "critical"} or action in {"blocked", "dropped", "detected", "deny"} else "event"
    devid = raw.get("devid", "")
    logid = raw.get("logid", "")
    sessionid = raw.get("sessionid", "")

    if etime:
        event_id = f"fgt-{devid}-{etime}-{logid}-{sessionid}"
    else:
        event_key = "|".join(str(raw.get(k, "")) for k in ("eventtime", "devid", "logid", "sessionid", "srcip", "dstip", "action", "user"))
        event_id = hashlib.sha256(event_key.encode()).hexdigest()[:32]

    ctx = {}
    if status:
        ctx["status"] = status
    if "catdesc" in raw:
        ctx["catdesc"] = raw["catdesc"]

    return NormalizedEventRecord(
        event_id=event_id,
        timestamp=timestamp,
        timestamp_us=ts_us,
        event_kind=event_kind,
        category=category,
        action=action,
        severity=severity,
        host=raw.get("devname") or devid or None,
        source_ip=raw.get("srcip"),
        destination_ip=raw.get("dstip"),
        user=raw.get("user"),
        process_name=raw.get("app"),
        process_id=sessionid or None,
        command_line=raw.get("msg") or raw.get("logdesc"),
        file_path=raw.get("filename"),
        domain=raw.get("hostname"),
        raw_event=raw,
        rule_context=ctx,
    )
