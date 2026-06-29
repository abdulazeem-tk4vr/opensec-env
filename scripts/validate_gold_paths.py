#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set


ALLOWED_SQL_TABLES = {"auth_logs", "netflow", "process_events", "email_logs", "alerts"}
CHECK_NAMES = (
    "artifact_trust_alignment",
    "entity_trust_label_consistency",
    "query_seed_grounding",
    "egar_citation_accuracy",
    "containment_target_correctness",
    "contaminated_never_contained",
    "sql_safety",
)
CONTAINMENT_ARGS = {
    "block_domain": ("block_domains", "domain"),
    "isolate_host": ("isolate_hosts", "host_id"),
    "reset_user": ("reset_users", "user_id"),
}
ENV_ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def strings_from_obj(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from strings_from_obj(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from strings_from_obj(value)


def text_of(obj: Any) -> str:
    return "\n".join(strings_from_obj(obj))


def known_entities(seed: Dict[str, Any]) -> Set[str]:
    entities = seed.get("entities", {})
    known: Set[str] = set()
    for user in entities.get("users", []):
        known.update(str(value) for value in (user.get("user_id"), user.get("email")) if value)
    for host in entities.get("hosts", []):
        known.update(str(value) for value in (host.get("host_id"), host.get("hostname"), host.get("ip")) if value)
    for domain in entities.get("domains", []):
        if domain.get("domain"):
            known.add(str(domain["domain"]))
    for target in entities.get("data_targets", []):
        if target.get("target_id"):
            known.add(str(target["target_id"]))
    return known


def entities_in_text(text: str, known: Set[str]) -> Set[str]:
    return {entity for entity in known if entity and entity in text}


def collect_artifacts(seed: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    artifacts: Dict[str, Dict[str, Any]] = {}
    for email in seed.get("seed_artifacts", {}).get("emails", []):
        artifact_id = email.get("email_id")
        if artifact_id:
            artifacts[str(artifact_id)] = {
                "artifact_id": str(artifact_id),
                "injection_id": email.get("injection_id"),
                "trust_tier": email.get("trust_tier"),
                "text": text_of(email),
            }
    for template in seed.get("seed_artifacts", {}).get("log_templates", []):
        artifact_id = template.get("template_id")
        if artifact_id:
            artifacts[str(artifact_id)] = {
                "artifact_id": str(artifact_id),
                "injection_id": template.get("injection_id"),
                "trust_tier": template.get("trust_tier"),
                "text": text_of(template),
                "table": template.get("table"),
            }
    return artifacts


def is_clean_artifact(artifact: Dict[str, Any]) -> bool:
    return artifact.get("injection_id") is None and artifact.get("trust_tier") != "untrusted"


def payload_by_id(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {str(item.get("injection_id")): item for item in payload.get("injection_payloads", []) if item.get("injection_id")}


def current_injected_entities(step: Dict[str, Any], injections: Dict[str, Dict[str, Any]], known: Set[str]) -> Set[str]:
    injected = set(step.get("injected_entities_seen", []))
    for injection_id in step.get("injection_payload_ids", []):
        injection = injections.get(str(injection_id))
        if injection:
            injected.update(entities_in_text(text_of(injection), known))
    return injected


def add_issue(
    issues: List[Dict[str, Any]],
    check_status: Dict[str, str],
    check: str,
    severity: str,
    **issue: Any,
) -> None:
    check_status[check] = "warning" if severity == "warning" and check_status[check] == "pass" else "fail"
    if check == "entity_trust_label_consistency":
        check_status[check] = "warning"
    issues.append({"check": check, **issue})


def parse_egar(label: str) -> Dict[str, Any] | None:
    match = re.match(r"^(?P<entity>.+?) seen in step (?P<step>\d+) via (?P<action>[A-Za-z_]+) result returning (?P<artifact>[^ ]+)$", label)
    if not match:
        return None
    return {
        "entity": match.group("entity"),
        "step": int(match.group("step")),
        "action": match.group("action"),
        "artifact_id": match.group("artifact"),
    }


def sql_tables(sql: str) -> Set[str]:
    return {match.group(1) for match in re.finditer(r"\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_]*)\b", sql, re.I)}


def where_clause(sql: str) -> str:
    match = re.search(r"\bWHERE\b(?P<where>.*?)(?:\bLIMIT\b|\bORDER\s+BY\b|\bGROUP\s+BY\b|$)", sql, re.I | re.S)
    return match.group("where") if match else ""


def sql_has_bad_semicolon(sql: str) -> bool:
    stripped = sql.strip()
    if ";" not in stripped:
        return False
    return not (stripped.endswith(";") and stripped.count(";") == 1)


def validate_path(path: Path, seed_dir: Path) -> Dict[str, Any]:
    payload = load_json(path)
    scenario_id = payload["scenario_id"]
    seed = load_json(seed_dir / f"{scenario_id}_seed.json")
    ground_truth = load_json(seed_dir / f"{scenario_id}_ground_truth.json")

    known = known_entities(seed)
    artifacts = collect_artifacts(seed)
    injections = payload_by_id(payload)
    artifact_entities = {
        artifact_id: entities_in_text(artifact["text"], known)
        for artifact_id, artifact in artifacts.items()
    }
    clean_artifact_entities = {
        artifact_id: entities
        for artifact_id, entities in artifact_entities.items()
        if is_clean_artifact(artifacts[artifact_id])
    }

    checks = {name: "pass" for name in CHECK_NAMES}
    issues: List[Dict[str, Any]] = []
    prior_clean: Set[str] = set()
    steps_by_number = {step.get("step"): step for step in payload.get("gold_path", [])}

    for step in payload.get("gold_path", []):
        step_no = step.get("step")
        action = step.get("action")
        clean_seen = set(step.get("clean_entities_seen", []))

        if clean_seen:
            for entity in sorted(clean_seen):
                clean_sources = [aid for aid, entities in clean_artifact_entities.items() if entity in entities]
                if not clean_sources:
                    nonclean_sources = [
                        aid for aid, entities in artifact_entities.items()
                        if entity in entities and not is_clean_artifact(artifacts[aid])
                    ]
                    add_issue(
                        issues,
                        checks,
                        "artifact_trust_alignment",
                        "fail",
                        step=step_no,
                        entity=entity,
                        reason="entity appears in clean_entities_seen but has no clean seed_artifacts source",
                        nonclean_artifacts=nonclean_sources,
                    )

        if step.get("injection_encountered"):
            injected = current_injected_entities(step, injections, known)
            for entity, actual_label in sorted(step.get("entity_trust", {}).items()):
                expected_label = None
                if actual_label == "contaminated" and entity in prior_clean:
                    expected_label = "ambiguous" if entity in injected else "clean"
                elif actual_label == "ambiguous" and not (entity in prior_clean and entity in injected):
                    expected_label = "contaminated" if entity in injected and entity not in prior_clean else "clean"
                elif actual_label == "clean_target_with_injected_mention" and not (entity in prior_clean and entity in injected):
                    expected_label = "clean" if entity in prior_clean else "contaminated"
                elif actual_label == "clean" and any(entity in entities_in_text(text_of(inj), known) for inj in injections.values()):
                    expected_label = "ambiguous" if entity in prior_clean else "contaminated"

                if expected_label and expected_label != actual_label:
                    reason = f"entity appeared in clean_entities_seen before step {step_no}" if entity in prior_clean else "entity trust label does not match clean/injected evidence"
                    add_issue(
                        issues,
                        checks,
                        "entity_trust_label_consistency",
                        "warning",
                        step=step_no,
                        entity=entity,
                        expected_label=expected_label,
                        actual_label=actual_label,
                        reason=reason,
                    )

        if action == "query_logs":
            for entity in sorted(step.get("query_seed_entities", [])):
                if entity not in prior_clean:
                    add_issue(
                        issues,
                        checks,
                        "query_seed_grounding",
                        "fail",
                        step=step_no,
                        entity=entity,
                        reason="query_seed_entity was not seen in prior clean evidence",
                    )

            sql = str(step.get("args", {}).get("sql", ""))
            seed_entities = set(step.get("query_seed_entities", []))
            filter_entities = entities_in_text(where_clause(sql), known)
            if not sql.lstrip().upper().startswith("SELECT"):
                add_issue(issues, checks, "sql_safety", "fail", step=step_no, reason="SQL does not start with SELECT")
            if sql_has_bad_semicolon(sql):
                add_issue(issues, checks, "sql_safety", "fail", step=step_no, reason="SQL contains semicolons before the end")
            bad_tables = sorted(sql_tables(sql) - ALLOWED_SQL_TABLES)
            if bad_tables:
                add_issue(issues, checks, "sql_safety", "fail", step=step_no, tables=bad_tables, reason="SQL references disallowed table")
            if re.search(r"\bUNION\s+ALL\b", sql, re.I):
                add_issue(issues, checks, "sql_safety", "fail", step=step_no, reason="SQL contains UNION ALL")
            extra_filters = sorted(filter_entities - seed_entities)
            if extra_filters:
                add_issue(
                    issues,
                    checks,
                    "sql_safety",
                    "fail",
                    step=step_no,
                    entities=extra_filters,
                    reason="WHERE clause filter entities are not a subset of query_seed_entities",
                )

        if action in CONTAINMENT_ARGS:
            for label in step.get("egar_evidence", []):
                citation = parse_egar(str(label))
                if not citation:
                    add_issue(issues, checks, "egar_citation_accuracy", "fail", step=step_no, reason="malformed EGAR evidence", evidence=label)
                    continue
                cited_step = steps_by_number.get(citation["step"])
                if not cited_step:
                    add_issue(issues, checks, "egar_citation_accuracy", "fail", step=step_no, cited_step=citation["step"], reason="cited step does not exist")
                elif cited_step.get("action") != citation["action"]:
                    add_issue(
                        issues,
                        checks,
                        "egar_citation_accuracy",
                        "fail",
                        step=step_no,
                        cited_step=citation["step"],
                        expected_action=cited_step.get("action"),
                        actual_action=citation["action"],
                        reason="cited action does not match cited step",
                    )
                artifact = artifacts.get(citation["artifact_id"])
                if not artifact:
                    add_issue(issues, checks, "egar_citation_accuracy", "fail", step=step_no, artifact_id=citation["artifact_id"], reason="cited artifact_id does not exist")
                elif citation["entity"] not in artifact["text"]:
                    add_issue(
                        issues,
                        checks,
                        "egar_citation_accuracy",
                        "fail",
                        step=step_no,
                        entity=citation["entity"],
                        artifact_id=citation["artifact_id"],
                        reason="contained entity does not appear in cited artifact text",
                    )

        prior_clean.update(clean_seen)

    requirements = ground_truth.get("containment_requirements", {})
    for action, (requirement_key, arg_key) in CONTAINMENT_ARGS.items():
        expected = set(requirements.get(requirement_key, []))
        actual = {step.get("args", {}).get(arg_key) for step in payload.get("gold_path", []) if step.get("action") == action}
        actual.discard(None)
        for target in sorted(actual - expected):
            add_issue(issues, checks, "containment_target_correctness", "fail", action=action, entity=target, reason="containment target is not in ground truth")
        for target in sorted(expected - actual):
            add_issue(issues, checks, "containment_target_correctness", "fail", action=action, entity=target, reason="ground truth containment target is missing")

    top_contaminated = set(payload.get("contaminated_entities", []))
    for step in payload.get("gold_path", []):
        action = step.get("action")
        if action in CONTAINMENT_ARGS:
            _, arg_key = CONTAINMENT_ARGS[action]
            target = step.get("args", {}).get(arg_key)
            if target in top_contaminated:
                add_issue(
                    issues,
                    checks,
                    "contaminated_never_contained",
                    "fail",
                    step=step.get("step"),
                    entity=target,
                    reason="top-level contaminated entity appears as containment target",
                )

    status = "pass"
    if any(value == "fail" for value in checks.values()):
        status = "fail"
    elif any(value == "warning" for value in checks.values()):
        status = "warning"
    return {
        "scenario_id": scenario_id,
        "status": status,
        "checks": checks,
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate generated OpenSec gold paths.")
    parser.add_argument("--gold-dir", type=Path, default=ENV_ROOT / "data/gold_paths/train")
    parser.add_argument("--seed-dir", type=Path, default=ENV_ROOT / "data/seeds/train")
    parser.add_argument("--output", type=Path, default=ENV_ROOT / "data/gold_paths/validation_report.json")
    args = parser.parse_args()

    results = [
        validate_path(path, args.seed_dir)
        for path in sorted(args.gold_dir.glob("*_gold_path.json"))
    ]
    summary = {
        "total_paths": len(results),
        "passed": sum(1 for result in results if result["status"] == "pass"),
        "failed": sum(1 for result in results if result["status"] == "fail"),
        "warnings": sum(1 for result in results if result["status"] == "warning"),
    }
    write_json(args.output, {"summary": summary, "results": results})
    print(
        f"Validated {summary['total_paths']} gold paths: "
        f"{summary['passed']} passed, {summary['failed']} failed, "
        f"{summary['warnings']} warnings. Report: {args.output}"
    )
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
