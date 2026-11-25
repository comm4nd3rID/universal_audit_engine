
from __future__ import annotations

import re


class UnsafeRegexError(ValueError):
    pass


MAX_PATTERN_LENGTH = 4096
MAX_INPUT_LENGTH = 2_000_000

# Conservative checks for common catastrophic-backtracking constructions.
NESTED_QUANTIFIER = re.compile(r"\([^)]{0,300}[+*][^)]*\)[+*{]")
AMBIGUOUS_ALTERNATION = re.compile(r"\((?:\?:)?[^)]*\|[^)]*\)[+*{]")


def compile_safe(pattern: str) -> re.Pattern:
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise UnsafeRegexError(f"Regex exceeds {MAX_PATTERN_LENGTH} characters")
    if NESTED_QUANTIFIER.search(pattern) or AMBIGUOUS_ALTERNATION.search(pattern):
        raise UnsafeRegexError("Regex rejected by conservative ReDoS guard")
    try:
        return re.compile(pattern, re.MULTILINE)
    except re.error as exc:
        raise UnsafeRegexError(f"Invalid regex: {exc}") from exc


def search(pattern: str, text: str) -> bool:
    if len(text) > MAX_INPUT_LENGTH:
        text = text[:MAX_INPUT_LENGTH]
    return bool(compile_safe(pattern).search(text))


def find_lines(pattern: str, text: str) -> list[str]:
    compiled = compile_safe(pattern)
    return [line for line in text.splitlines() if compiled.search(line)]
