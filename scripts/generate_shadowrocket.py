#!/usr/bin/env python3
"""Generate validated Shadowrocket and OpenClash rules from rules.list."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

SOURCE = Path("rules.list")
MAPPING_FILE = Path("config/policy-map.json")
SHADOWROCKET_OUTPUT = Path("generated/shadowrocket.module")
OPENCLASH_OUTPUT = Path("generated/openclash")

SUPPORTED_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-SET",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "USER-AGENT",
    "URL-REGEX",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "PROTOCOL",
    "NETWORK",
    "RULE-SET",
    "SCRIPT",
    "AND",
    "OR",
    "NOT",
    "FINAL",
}
BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PROXY"}
LOGICAL_TYPES = {"AND", "OR", "NOT"}


def load_mappings() -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    if not MAPPING_FILE.is_file():
        raise SystemExit(f"mapping file not found: {MAPPING_FILE}")
    try:
        data = json.loads(MAPPING_FILE.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid mapping file {MAPPING_FILE}: {exc}") from exc

    shadowrocket = data.get("shadowrocket")
    if not isinstance(shadowrocket, dict) or not shadowrocket:
        raise SystemExit(f"{MAPPING_FILE} must contain a non-empty 'shadowrocket' object")
    if any(
        not isinstance(source, str)
        or not source.strip()
        or not isinstance(target, str)
        or not target.strip()
        for source, target in shadowrocket.items()
    ):
        raise SystemExit(
            f"{MAPPING_FILE}: all shadowrocket mappings must be non-empty strings"
        )

    openclash = data.get("openclash")
    if not isinstance(openclash, dict) or not openclash:
        raise SystemExit(f"{MAPPING_FILE} must contain a non-empty 'openclash' object")

    normalized_openclash: dict[str, dict[str, str]] = {}
    policy_by_file: dict[str, str] = {}
    for source, settings in openclash.items():
        if not isinstance(source, str) or not source.strip() or not isinstance(settings, dict):
            raise SystemExit(f"{MAPPING_FILE}: invalid openclash mapping for {source!r}")
        policy = settings.get("policy")
        file_name = settings.get("file")
        if not isinstance(policy, str) or not policy.strip():
            raise SystemExit(f"{MAPPING_FILE}: {source!r} needs a non-empty policy")
        if not isinstance(file_name, str) or not file_name.strip():
            raise SystemExit(f"{MAPPING_FILE}: {source!r} needs a non-empty file")
        file_name = file_name.strip()
        file_path = Path(file_name)
        if file_path.name != file_name or file_path.suffix != ".yaml":
            raise SystemExit(
                f"{MAPPING_FILE}: {source!r} file must be a safe .yaml basename"
            )
        existing_policy = policy_by_file.get(file_name)
        if existing_policy is not None and existing_policy != policy.strip():
            raise SystemExit(
                f"{MAPPING_FILE}: {file_name!r} cannot target multiple OpenClash policies"
            )
        policy_by_file[file_name] = policy.strip()
        normalized_openclash[source.strip()] = {
            "policy": policy.strip(),
            "file": file_name,
        }

    return (
        {source.strip(): target.strip() for source, target in shadowrocket.items()},
        normalized_openclash,
    )


def parse_rule(line: str, line_number: int) -> tuple[list[str], int]:
    parts = [part.strip() for part in line.split(",")]
    rule_type = parts[0].upper()

    minimum_fields = 2 if rule_type == "FINAL" else 3
    if rule_type not in SUPPORTED_TYPES:
        raise ValueError(f"line {line_number}: unsupported rule type {parts[0]!r}")
    if len(parts) < minimum_fields or any(not part for part in parts[:minimum_fields]):
        raise ValueError(
            f"line {line_number}: {rule_type} requires at least {minimum_fields} non-empty fields"
        )

    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(parts[1], strict=False)
        except ValueError as exc:
            raise ValueError(f"line {line_number}: invalid CIDR {parts[1]!r}") from exc
        expected_version = 4 if rule_type == "IP-CIDR" else 6
        if network.version != expected_version:
            raise ValueError(
                f"line {line_number}: {rule_type} requires an IPv{expected_version} network"
            )

    if rule_type == "FINAL":
        policy_index = 1
    elif rule_type in LOGICAL_TYPES:
        policy_index = -1
    else:
        policy_index = 2
    return parts, policy_index


def build_shadowrocket_rule(
    parts: list[str], policy_index: int, policy_map: dict[str, str], line_number: int
) -> str:
    output_parts = parts.copy()
    source_policy = output_parts[policy_index]
    if source_policy in policy_map:
        output_parts[policy_index] = policy_map[source_policy]
    elif source_policy.upper() in BUILTIN_POLICIES:
        output_parts[policy_index] = source_policy.upper()
    else:
        raise ValueError(
            f"line {line_number}: policy {source_policy!r} has no shadowrocket mapping"
        )
    return ",".join(output_parts)


def build_openclash_rule(
    parts: list[str], policy_index: int, policy_map: dict[str, dict[str, str]], line_number: int
) -> tuple[str, str, str]:
    source_policy = parts[policy_index]
    settings = policy_map.get(source_policy)
    if settings is None:
        raise ValueError(
            f"line {line_number}: policy {source_policy!r} has no openclash mapping"
        )
    output_parts = parts.copy()
    del output_parts[policy_index]
    return settings["file"], settings["policy"], ",".join(output_parts)


def write_shadowrocket(rules: list[str]) -> None:
    module = "\n".join(
        [
            "#!name=myrule",
            "#!desc=由 GitHub Actions 从 rules.list 自动生成，请勿手动编辑",
            "",
            "[Rule]",
            *rules,
            "",
        ]
    )
    SHADOWROCKET_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    SHADOWROCKET_OUTPUT.write_text(module, encoding="utf-8", newline="\n")


def write_openclash(groups: dict[str, dict[str, object]]) -> None:
    OPENCLASH_OUTPUT.mkdir(parents=True, exist_ok=True)
    expected_files = set(groups)
    for existing in OPENCLASH_OUTPUT.glob("*.yaml"):
        if existing.name not in expected_files:
            existing.unlink()

    for file_name, group in sorted(groups.items()):
        policy = str(group["policy"])
        rules = list(group["rules"])
        content = [f"# policy: {policy}", "payload:"]
        content.extend(f"  - {json.dumps(rule, ensure_ascii=False)}" for rule in rules)
        (OPENCLASH_OUTPUT / file_name).write_text(
            "\n".join(content) + "\n", encoding="utf-8", newline="\n"
        )


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"input file not found: {SOURCE}")

    shadowrocket_map, openclash_map = load_mappings()
    shadowrocket_rules: list[str] = []
    openclash_groups: dict[str, dict[str, object]] = {}
    errors: list[str] = []

    for line_number, raw_line in enumerate(
        SOURCE.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        try:
            parts, policy_index = parse_rule(line, line_number)
            shadowrocket_rules.append(
                build_shadowrocket_rule(parts, policy_index, shadowrocket_map, line_number)
            )
            file_name, policy, provider_rule = build_openclash_rule(
                parts, policy_index, openclash_map, line_number
            )
            group = openclash_groups.setdefault(
                file_name, {"policy": policy, "rules": []}
            )
            group_rules = group["rules"]
            if isinstance(group_rules, list) and provider_rule not in group_rules:
                group_rules.append(provider_rule)
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        raise SystemExit("rules.list validation failed:\n" + "\n".join(errors))
    if not shadowrocket_rules:
        raise SystemExit("rules.list contains no valid rules")
    if not openclash_groups:
        raise SystemExit("rules.list produced no OpenClash provider rules")

    write_shadowrocket(shadowrocket_rules)
    write_openclash(openclash_groups)
    print(
        f"generated {SHADOWROCKET_OUTPUT} and {len(openclash_groups)} OpenClash provider(s) "
        f"from {len(shadowrocket_rules)} rule(s)"
    )


if __name__ == "__main__":
    main()
