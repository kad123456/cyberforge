
"""Bounded, streaming inspection for an unknown competition telemetry file."""
import argparse
import json
from collections import Counter
from pathlib import Path

def flatten(value, prefix=""):
    if isinstance(value, dict):
        for key, child in value.items(): yield from flatten(child, f"{prefix}.{key}" if prefix else key)
    else: yield prefix

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("file", nargs="?", default="data/edr_events.json"); parser.add_argument("--sample",type=int,default=200)
    args=parser.parse_args(); path=Path(args.file)
    if not path.exists(): raise SystemExit(f"File not found: {path}")
    fields=Counter(); missing=Counter(); samples=[]; valid=invalid=0; format_name=None
    with path.open("r",encoding="utf-8",errors="replace") as source:
        for line in source:
            if not line.strip(): continue
            if format_name is None: format_name="CEF" if line.lstrip().startswith("CEF:") else "JSONL"
            if valid+invalid>=args.sample: break
            try:
                value=json.loads(line); valid+=1; samples.append(value)
                present=set(flatten(value)); fields.update(present)
            except json.JSONDecodeError: invalid+=1
    for common in ["@timestamp","event.id","host.name","user.name","process.name","source.ip","destination.ip"]: missing[common]=valid-fields[common]
    print(f"File: {path.resolve()}\nSize: {path.stat().st_size:,} bytes\nDetected format: {format_name}\nInspected: {valid+invalid:,} records ({valid} JSON-valid, {invalid} invalid)")
    print("\nFields:"); print("\n".join(f"- {field}: present in {count}/{valid}" for field,count in fields.most_common()))
    print("\nCommon-field missing counts:"); print("\n".join(f"- {field}: {count}" for field,count in missing.items()))
    print("\nSample records:"); print(json.dumps(samples[:3],indent=2)[:12000])
if __name__=="__main__": main()

