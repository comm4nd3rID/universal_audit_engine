
from __future__ import annotations

import hashlib
import json
from typing import Any

from universal_audit.core.models import (
    AuditDocument, CanonicalAudit, CanonicalNode, CheckDefinition
)


PLATFORM_MAP = {
    "cisco": "cisco_ios_xe",
    "fortigate": "fortigate",
    "unix": "vmware_esxi",
}


def _canonical_check_type(family: str, fields: dict[str, Any]) -> str:
    original = str(fields.get("type", "")).strip().upper()
    family = family.lower()

    if family == "cisco":
        return {
            "CONFIG_CHECK": "CISCO_CONFIG_CHECK",
            "CONFIG_CHECK_NOT": "CISCO_CONFIG_CHECK_NOT",
            "BANNER_CHECK": "CISCO_BANNER_CHECK",
        }.get(original, "UNSUPPORTED")

    if family == "fortigate":
        if original == "BANNER_CHECK":
            return "FORTIGATE_BANNER_CHECK"
        if fields.get("cmd"):
            return "FORTIGATE_COMMAND"
        if fields.get("context") and (fields.get("regex") or fields.get("expect") or fields.get("not_expect")):
            return "FORTIGATE_CONTEXT_REGEX"
        return "UNSUPPORTED"

    if family == "unix":
        return {
            "CMD_EXEC": "UNIX_COMMAND",
            "FILE_CONTENT_CHECK": "UNIX_FILE_CONTENT",
            "BANNER_CHECK": "UNIX_BANNER",
        }.get(original, "UNSUPPORTED")

    return "UNSUPPORTED"


def normalize(document: AuditDocument) -> CanonicalAudit:
    family = document.syntax_family.strip()
    platform = PLATFORM_MAP.get(family.lower(), "unknown")
    if family.lower() == "unix":
        spec_name = str(document.metadata.get("spec", {}).get("name", "")).lower()
        if "esxi" in spec_name or "vmware" in spec_name:
            platform = "vmware_esxi"

    def convert(ast_node, path: tuple[int, ...]) -> CanonicalNode:
        tag = ast_node.tag.lower()
        attrs = dict(ast_node.attrs)
        fields = dict(ast_node.fields)
        source = dict(ast_node.source_location)

        if tag in ("item", "custom_item"):
            canonical_type = _canonical_check_type(family, fields)
            raw = {
                "tag": tag,
                "fields": fields,
                "raw_text": ast_node.raw_text,
            }
            stable_material = json.dumps(
                {"hash": document.file_hash, "path": path, "raw": raw},
                sort_keys=True, ensure_ascii=False
            )
            check_id = hashlib.sha256(stable_material.encode("utf-8")).hexdigest()[:24]
            references = []
            see_also = fields.get("see_also")
            if isinstance(see_also, str) and see_also.strip():
                references.append(see_also.strip())
            reference_values = fields.get("reference")
            if isinstance(reference_values, str):
                references.extend(
                    item.strip() for item in reference_values.split(",") if item.strip()
                )
            check = CheckDefinition(
                check_id=check_id,
                description=str(fields.get("description") or f"Unnamed check at line {source.get('line', '?')}"),
                original_check_type=str(fields.get("type")) if fields.get("type") is not None else None,
                canonical_check_type=canonical_type,
                platform=platform,
                parameters=fields.copy(),
                expected=(
                    fields.get("content") or fields.get("regex") or fields.get("item")
                    if family.lower() == "cisco"
                    else fields.get("expect") or fields.get("not_expect") or fields.get("content") or fields.get("regex")
                ),
                context=fields.get("context"),
                severity=str(fields.get("severity")).upper() if fields.get("severity") else None,
                references=references,
                remediation=fields.get("solution"),
                raw_fields=fields.copy(),
                raw_definition=raw,
                source_location=source,
            )
            return CanonicalNode(
                node_type="CHECK", attrs=attrs, check=check, fields=fields,
                source_location=source, raw_text=ast_node.raw_text
            )

        children = [
            convert(child, path + (index,))
            for index, child in enumerate(ast_node.children)
        ]

        node_type = {
            "if": "IF",
            "condition": "CONDITION",
            "then": "THEN",
            "else": "ELSE",
            "report": "REPORT",
        }.get(tag, "CONTAINER" if tag == "check_type" else "UNKNOWN")

        unknown_check = None
        if node_type == "UNKNOWN":
            raw = {"tag": tag, "fields": fields, "raw_text": ast_node.raw_text}
            stable_material = json.dumps(
                {"hash": document.file_hash, "path": path, "raw": raw},
                sort_keys=True, ensure_ascii=False
            )
            unknown_check = CheckDefinition(
                check_id=hashlib.sha256(stable_material.encode("utf-8")).hexdigest()[:24],
                description=str(fields.get("description") or f"Unsupported audit node <{tag}>"),
                original_check_type=str(fields.get("type")) if fields.get("type") is not None else None,
                canonical_check_type="UNSUPPORTED",
                platform=platform,
                parameters=fields.copy(),
                expected=fields.get("expect"),
                context=fields.get("context"),
                severity=str(fields.get("severity")).upper() if fields.get("severity") else None,
                references=[],
                remediation=fields.get("solution"),
                raw_fields=fields.copy(),
                raw_definition=raw,
                source_location=source,
            )

        return CanonicalNode(
            node_type=node_type,
            attrs=attrs,
            children=children,
            check=unknown_check,
            fields=fields,
            source_location=source,
            raw_text=ast_node.raw_text,
        )

    nodes = [convert(node, (i,)) for i, node in enumerate(document.nodes)]
    return CanonicalAudit(
        source_path=document.source_path,
        file_hash=document.file_hash,
        syntax_family=family,
        platform=platform,
        metadata=document.metadata,
        variables=document.variables,
        nodes=nodes,
        raw_header=document.raw_header,
        warnings=document.warnings.copy(),
    )
