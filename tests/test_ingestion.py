import json
import pytest
from backend.ingestion.parser import detect_format, parse_line, normalize

def test_jsonl_normalizes_generator_shape():
    raw={"@timestamp":"2026-01-01T00:00:00Z","event":{"id":"e1","category":["process"],"kind":"event","action":"process_created","severity":1},"host":{"name":"WS-01"},"user":{"name":"analyst"},"process":{"name":"powershell.exe","parent":{"name":"winword.exe"},"command_line":"powershell -enc demo"}}
    event=normalize(parse_line(json.dumps(raw)))
    assert event.event_id=="e1" and event.host=="WS-01" and event.parent_process=="winword.exe"

def test_cef_parse_and_normalize():
    event=normalize(parse_line("CEF:0|Vendor|EDR|1|sig|alert|7|rt=2026-01-01T00:00:00Z dvchost=WS-01 suser=alex cat=network act=connection externalId=e2 dproc=powershell.exe cs2=T1059.001"))
    assert event.technique_id=="T1059.001" and event.host=="WS-01"

def test_invalid_json_is_rejected():
    with pytest.raises(json.JSONDecodeError): parse_line("not a JSON record")

def test_missing_fields_are_safe():
    assert normalize(parse_line('{"event":{"id":"e3"}}')).category=="unknown"

def test_fortigate_key_value_normalizes():
    line='date=2026-10-23 time=08:48:26 tz="+0530" devname="FGT" logid="0100032002" type="event" subtype="system" level="alert" user="admin" srcip=209.50.167.232 dstip=10.10.99.1 action="login" status="failed"'
    event=normalize(parse_line(line))
    assert event.category=="authentication" and event.severity=="critical" and event.source_ip=="209.50.167.232"
