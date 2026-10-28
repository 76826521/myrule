#!/usr/bin/env python3
"""Generate a validated Shadowrocket module from rules.list."""

from __future__ import annotations

import ipaddress
from pathlib import Path

SOURCE = Path("rules.list")
OUTPUT = Path("generated/shadowrocket.module")

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


def validate_rule(line: str, line_number: int) -> str:
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

    return ",".join(parts)


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"input file not found: {SOURCE}")

    rules: list[str] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate(
        SOURCE.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        try:
            rules.append(validate_rule(line, line_number))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        raise SystemExit("rules.list validation failed:\n" + "\n".join(errors))
    if not rules:
        raise SystemExit("rules.list contains no valid rules")

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
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(module, encoding="utf-8", newline="\n")
    print(f"generated {OUTPUT} with {len(rules)} rule(s)")


if __name__ == "__main__":
    main()
