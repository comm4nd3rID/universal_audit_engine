
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from universal_audit.core.models import VariableDefinition


class MetadataExtractor:
    def parse(self, lines: list[str]) -> tuple[dict[str, Any], list[VariableDefinition], list[str]]:
        text = "\n".join(lines)
        match = re.search(
            r"(?ims)^\s*#\s*<ui_metadata>\s*$\n(.*?)^\s*#\s*</ui_metadata>\s*$",
            text
        )
        if not match:
            return {}, [], ["ui_metadata block not found"]
        block = match.group(0).splitlines()
        clean_lines = [re.sub(r"^\s*# ?", "", line, count=1) for line in block]
        warnings: list[str] = []
        try:
            root = ET.fromstring("\n".join(clean_lines))
            metadata: dict[str, Any] = {}
            for key in ("display_name", "labels", "benchmark_refs"):
                value = root.findtext(key)
                if value is not None:
                    metadata[key] = value.strip()
            spec = root.find("spec")
            if spec is not None:
                metadata["spec"] = {
                    child.tag: (child.text or "").strip()
                    for child in list(spec)
                }
            if metadata.get("labels"):
                metadata["labels"] = [x.strip() for x in metadata["labels"].split(",") if x.strip()]
            if metadata.get("benchmark_refs"):
                metadata["benchmark_refs"] = [
                    x.strip() for x in metadata["benchmark_refs"].split(",") if x.strip()
                ]
            variables: list[VariableDefinition] = []
            variables_node = root.find("variables")
            if variables_node is not None:
                for var in variables_node.findall("variable"):
                    variables.append(VariableDefinition(
                        name=(var.findtext("name") or "").strip(),
                        default=_none_if_empty(var.findtext("default")),
                        description=_none_if_empty(var.findtext("description")),
                        info=_none_if_empty(var.findtext("info")),
                        value_type=_none_if_empty(var.findtext("value_type")),
                    ))
            return metadata, variables, warnings
        except ET.ParseError as exc:
            warnings.append(f"ui_metadata XML parse warning: {exc}")
            metadata = {}
            for key in ("display_name", "type", "name", "profile", "version", "link"):
                found = re.search(rf"<{key}>(.*?)</{key}>", "\n".join(clean_lines), re.S | re.I)
                if found:
                    metadata[key] = found.group(1).strip()
            spec_keys = ("type", "name", "profile", "version", "link")
            metadata["spec"] = {k: metadata[k] for k in spec_keys if k in metadata}
            return metadata, [], warnings


def _none_if_empty(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None
