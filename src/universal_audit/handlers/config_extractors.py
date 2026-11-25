
from __future__ import annotations

from universal_audit.security.regex_safety import search


def extract_cisco_context(config: str, context_pattern: str | None) -> str:
    if not context_pattern:
        return config
    lines = config.splitlines()
    blocks: list[str] = []
    for idx, line in enumerate(lines):
        if search(context_pattern, line):
            selected = [line]
            for following in lines[idx + 1:]:
                if not following.strip():
                    selected.append(following)
                    continue
                if following[:1].isspace():
                    selected.append(following)
                else:
                    break
            blocks.append("\n".join(selected))
    return "\n\n".join(blocks)


def extract_fortigate_context(config: str, context_pattern: str | None) -> str:
    if not context_pattern:
        return config
    lines = config.splitlines()
    blocks: list[str] = []
    for idx, line in enumerate(lines):
        if not search(context_pattern, line):
            continue
        selected = [line]
        first = line.strip().lower().startswith("config ")
        depth = 1 if first else 0
        for following in lines[idx + 1:]:
            selected.append(following)
            stripped = following.strip().lower()
            if stripped.startswith("config "):
                depth += 1
            elif stripped == "end":
                depth -= 1
                if depth <= 0:
                    break
        blocks.append("\n".join(selected))
    return "\n\n".join(blocks)


def extract_cisco_banner(config: str, item_pattern: str | None) -> str:
    if not item_pattern:
        return ""
    lines = config.splitlines()
    for idx, line in enumerate(lines):
        if not search(item_pattern, line):
            continue
        parts = line.strip().split()
        if len(parts) < 3:
            return line
        delimiter = parts[2]
        selected = [line]
        for following in lines[idx + 1:]:
            selected.append(following)
            if following.strip() == delimiter:
                return "\n".join(selected)
        # A missing terminator is incomplete evidence; do not search the rest
        # of the configuration for a coincidental banner text match.
        return line
    return ""
