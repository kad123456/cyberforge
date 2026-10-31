from __future__ import annotations
import json
from collections import deque
from datetime import datetime, timedelta
import heapq
import itertools
from uuid import NAMESPACE_URL, uuid5
from backend.config import RULES_PATH
from backend.mitre import mapping
from backend.models import Detection, NormalizedEvent

class DetectionEngine:
    def __init__(self, rule_path=RULES_PATH):
        try:
            self.rules = json.loads(rule_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not load detection rules from {rule_path}: {exc}") from exc
        self._validate_rules(self.rules)
        self._unrestricted_rules = []
        self._rules_by_category = {}
        for rule in self.rules:
            conditions = []
            categories = None
            for field, expected in rule.get("event", {}).items():
                values = expected if isinstance(expected, list) else [expected]
                needles = tuple(str(value).casefold() for value in values)
                conditions.append((field, needles))
                if field == "category":
                    categories = needles
            compiled = {
                "rule": rule,
                "event": tuple(conditions),
                "contains": tuple(str(value).casefold() for value in rule.get("contains", ())),
                "parent_in": tuple(str(value).casefold() for value in rule.get("parent_in", ())),
                "domain_contains": tuple(str(value).casefold() for value in rule.get("domain_contains", ())),
                "registry_contains": tuple(str(value).casefold() for value in rule.get("registry_contains", ())),
                "file_contains": tuple(str(value).casefold() for value in rule.get("file_contains", ())),
                "raw_contains": {
                    field: tuple(str(value).casefold() for value in needles)
                    for field, needles in rule.get("raw_contains", {}).items()
                },
            }
            if categories:
                for category in categories:
                    self._rules_by_category.setdefault(category, []).append(compiled)
            else:
                self._unrestricted_rules.append(compiled)
        # Precompute candidate rules per category to eliminate list allocations in detect_batch
        self._compiled_by_category: dict[str, list[dict]] = {
            cat: self._unrestricted_rules + rules
            for cat, rules in self._rules_by_category.items()
        }
        self.failed: dict[tuple[str | None, str | None], deque] = {}
        self._failure_expiry = []
        self._failure_scheduled = set()
        self.file_modifications: dict[str | None, deque] = {}
        self._file_expiry = []
        self._file_scheduled = set()
        self._sequence = itertools.count()

    @staticmethod
    def _validate_rules(rules):
        if not isinstance(rules, list):
            raise ValueError("Detection rules must be a JSON array")
        ids = set()
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"Detection rule at index {index} must be an object")
            for field in ("id", "name", "severity", "technique_id", "confidence"):
                if field not in rule:
                    raise ValueError(f"Detection rule at index {index} is missing '{field}'")
            if rule["id"] in ids:
                raise ValueError(f"Duplicate detection rule id: {rule['id']}")
            ids.add(rule["id"])
            if rule["severity"] not in {"informational", "low", "medium", "high", "critical"}:
                raise ValueError(f"Detection rule {rule['id']} has an unsupported severity")
            if not isinstance(rule["confidence"], (int, float)) or not 0 <= rule["confidence"] <= 1:
                raise ValueError(f"Detection rule {rule['id']} confidence must be between 0 and 1")
            if not isinstance(rule.get("event", {}), dict):
                raise ValueError(f"Detection rule {rule['id']} event conditions must be an object")
            for field, expected in rule.get("event", {}).items():
                values = expected if isinstance(expected, list) else [expected]
                if not all(isinstance(value, str) for value in values):
                    raise ValueError(f"Detection rule {rule['id']} event condition '{field}' must contain strings")
            for field in ("contains", "parent_in", "domain_contains", "registry_contains", "file_contains"):
                values = rule.get(field, [])
                if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                    raise ValueError(f"Detection rule {rule['id']} field '{field}' must be an array of strings")
            raw_contains = rule.get("raw_contains", {})
            if not isinstance(raw_contains, dict) or any(
                not isinstance(field, str) or not isinstance(values, list) or not all(isinstance(value, str) for value in values)
                for field, values in raw_contains.items()
            ):
                raise ValueError(f"Detection rule {rule['id']} raw_contains must map field names to string arrays")

    def _expire_failures(self, timestamp):
        cutoff = timestamp - timedelta(minutes=15)
        while self._failure_expiry and self._failure_expiry[0][0] < cutoff:
            _, _, key = heapq.heappop(self._failure_expiry)
            self._failure_scheduled.discard(key)
            queue = self.failed.get(key)
            while queue and queue[0][0] < cutoff:
                queue.popleft()
            if not queue:
                self.failed.pop(key, None)
            else:
                heapq.heappush(self._failure_expiry, (queue[0][0] + timedelta(minutes=15), next(self._sequence), key))
                self._failure_scheduled.add(key)

        while self._file_expiry and self._file_expiry[0][0] < cutoff:
            _, _, host = heapq.heappop(self._file_expiry)
            self._file_scheduled.discard(host)
            queue = self.file_modifications.get(host)
            while queue and queue[0][0] < cutoff:
                queue.popleft()
            if not queue:
                self.file_modifications.pop(host, None)
            else:
                heapq.heappush(self._file_expiry, (queue[0][0] + timedelta(minutes=15), next(self._sequence), host))
                self._file_scheduled.add(host)

    @staticmethod
    def _contains(text, needles): return bool(text) and any(n.lower() in text.lower() for n in needles)

    @staticmethod
    def _contains_compiled(text, needles):
        if not text or not needles:
            return False
        normalized = str(text).casefold()
        return any(needle in normalized for needle in needles)

    def _matches(self, event: NormalizedEvent, compiled: dict) -> bool:
        for field, needles in compiled["event"]:
            actual = getattr(event, field, None)
            if actual is None or not any(needle in str(actual).casefold() for needle in needles):
                return False
        if compiled["contains"] and not self._contains_compiled(event.command_line, compiled["contains"]):
            return False
        if compiled["parent_in"] and not self._contains_compiled(event.parent_process, compiled["parent_in"]):
            return False
        if compiled["domain_contains"] and not self._contains_compiled(event.domain, compiled["domain_contains"]):
            return False
        if compiled["registry_contains"] and not self._contains_compiled(event.registry_path, compiled["registry_contains"]):
            return False
        if compiled["file_contains"] and not self._contains_compiled(event.file_path, compiled["file_contains"]):
            return False
        for field, needles in compiled["raw_contains"].items():
            context = event.rule_context or event.raw_event
            if not self._contains_compiled(context.get(field, ""), needles):
                return False
        return True

    def detect(self, events: list[NormalizedEvent]) -> list[Detection]:
        self.failed.clear()
        self._failure_expiry.clear()
        self._failure_scheduled.clear()
        self.file_modifications.clear()
        self._file_expiry.clear()
        self._file_scheduled.clear()
        return self.detect_batch(events)

    def detect_batch(self, events: list[NormalizedEvent]) -> list[Detection]:
        """Evaluate one bounded event batch while retaining compact state across batch boundaries."""
        if not events:
            return []
        found = []
        ransomware_exts = (".locked", ".encrypted", ".crypt", ".crypto", ".darkmatter", ".lockbit")

        # Expire old sliding window states once per batch or when timestamp advances significantly
        last_expire_ts = events[0].timestamp
        self._expire_failures(last_expire_ts)

        for event in events:
            ts = event.timestamp
            if (ts - last_expire_ts).total_seconds() > 30.0:
                self._expire_failures(ts)
                last_expire_ts = ts

            cat = (event.category or "").casefold()

            # Authentication sequence detection
            if cat == "authentication":
                context = event.rule_context or event.raw_event
                nested = context.get("event", {})
                outcome = context.get("outcome") or (nested.get("outcome") if isinstance(nested, dict) else None)
                result = str(outcome or context.get("status") or "").lower()
                action = str(event.action or "").lower()
                is_failure = result in {"failure", "failed", "deny", "denied"} or action in {"login_failed", "authentication_failure"}
                is_success = result in {"success", "succeeded", "allowed", "ok"} or action in {"login_success", "authentication_success"}
                key = (event.host, event.user)

                if is_failure:
                    failures = self.failed.setdefault(key, deque(maxlen=5))
                    failures.append((event.timestamp, event.event_id))
                    if key not in self._failure_scheduled:
                        heapq.heappush(self._failure_expiry, (failures[0][0] + timedelta(minutes=15), next(self._sequence), key))
                        self._failure_scheduled.add(key)
                    if len(failures) >= 5:
                        rule = {"id": "CS-AUTH-001", "name": "Repeated failed authentication", "severity": "medium", "technique_id": "T1110"}
                        found.append(self._alert(event, rule, min(0.95, 0.55 + len(failures) * .05), {
                            "failed_attempts": len(failures),
                            "window_minutes": 15,
                            "evidence_event_ids": [item[1] for item in failures],
                            "host": event.host,
                            "user": event.user,
                            "source_ip": event.source_ip,
                        }))
                elif is_success:
                    failures = self.failed.get(key, ())
                    if len(failures) >= 5:
                        rule = {"id": "CS-AUTH-002", "name": "Successful authentication after repeated failures", "severity": "high", "technique_id": "T1110"}
                        found.append(self._alert(event, rule, min(0.98, 0.68 + len(failures) * .04), {
                            "failed_attempts": len(failures),
                            "window_minutes": 15,
                            "failure_event_ids": [item[1] for item in failures],
                            "evidence_event_ids": [item[1] for item in failures] + [event.event_id],
                            "host": event.host,
                            "user": event.user,
                            "source_ip": event.source_ip,
                        }))

            # Ransomware mass file modification detection spanning batches
            elif cat == "file":
                action = str(event.action or "").lower()
                fp = str(event.file_path or "").casefold()
                if any(ext in fp for ext in ransomware_exts) or "rename" in action or "encrypt" in action:
                    fmod = self.file_modifications.setdefault(event.host, deque(maxlen=50))
                    fmod.append((event.timestamp, event.event_id))
                    if event.host not in self._file_scheduled:
                        heapq.heappush(self._file_expiry, (fmod[0][0] + timedelta(minutes=15), next(self._sequence), event.host))
                        self._file_scheduled.add(event.host)
                    if len(fmod) >= 3:
                        rule = {"id": "CS-RANSOM-001", "name": "Ransomware mass file modification activity", "severity": "critical", "technique_id": "T1486"}
                        found.append(self._alert(event, rule, 0.90, {
                            "host": event.host,
                            "user": event.user,
                            "file_count": len(fmod),
                            "window_minutes": 15,
                            "evidence_event_ids": [item[1] for item in fmod],
                            "last_file": event.file_path,
                        }))

            candidates = self._compiled_by_category.get(cat, self._unrestricted_rules)
            for compiled in candidates:
                rule = compiled["rule"]
                if self._matches(event, compiled):
                    found.append(self._alert(event, rule, rule["confidence"]))
        unique = {(d.event_id, d.rule_id): d for d in found}
        return list(unique.values())

    def _alert(self, event, rule, confidence, evidence=None):
        name, tactic = mapping(rule["technique_id"])
        detection_id = str(uuid5(NAMESPACE_URL, f"chainsight-ai:detection:{event.event_id}:{rule['id']}"))
        base_evidence = {
            "host": event.host,
            "user": event.user,
            "process": event.process_name,
            "command_line": event.command_line,
            "domain": event.domain,
            "registry_path": event.registry_path,
            "file_path": event.file_path,
            "evidence_event_ids": [event.event_id],
        }
        if evidence:
            base_evidence.update(evidence)
            if "evidence_event_ids" not in base_evidence:
                base_evidence["evidence_event_ids"] = [event.event_id]
        return Detection(
            detection_id=detection_id,
            event_id=event.event_id,
            rule_id=rule["id"],
            rule_name=rule["name"],
            severity=rule["severity"],
            technique_id=rule["technique_id"],
            technique_name=name or "Unknown",
            tactic=tactic or "Unknown",
            confidence=confidence,
            evidence=base_evidence,
        )

    def export_state(self) -> dict:
        """Export compact sliding-window state for checkpoint persistence."""
        return {
            "failed": {
                f"{k[0] or ''}|{k[1] or ''}": [(ts.isoformat(), eid) for ts, eid in v]
                for k, v in self.failed.items()
            },
            "file_modifications": {
                str(k or ""): [(ts.isoformat(), eid) for ts, eid in v]
                for k, v in self.file_modifications.items()
            },
        }

    def import_state(self, state: dict | None) -> None:
        """Restore sliding-window state when resuming an interrupted ingestion job."""
        if not state or not isinstance(state, dict):
            return
        self.failed.clear()
        self._failure_expiry.clear()
        self._failure_scheduled.clear()
        self.file_modifications.clear()
        self._file_expiry.clear()
        self._file_scheduled.clear()

        for k, v in state.get("failed", {}).items():
            host, _, user = k.partition("|")
            key = (host or None, user or None)
            entries = deque([(datetime.fromisoformat(ts), eid) for ts, eid in v], maxlen=5)
            if entries:
                self.failed[key] = entries
                heapq.heappush(self._failure_expiry, (entries[0][0] + timedelta(minutes=15), next(self._sequence), key))
                self._failure_scheduled.add(key)

        for host_str, v in state.get("file_modifications", {}).items():
            host = host_str or None
            entries = deque([(datetime.fromisoformat(ts), eid) for ts, eid in v], maxlen=50)
            if entries:
                self.file_modifications[host] = entries
                heapq.heappush(self._file_expiry, (entries[0][0] + timedelta(minutes=15), next(self._sequence), host))
                self._file_scheduled.add(host)
