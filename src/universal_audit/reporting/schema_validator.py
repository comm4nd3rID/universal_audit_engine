
from __future__ import annotations

import json
from pathlib import Path


class ReportSchemaValidator:
    def __init__(self, schema_path: str | Path | None = None):
        self.schema_path = Path(schema_path) if schema_path else Path(__file__).with_name("schema.json")

    def validate(self, report: dict) -> None:
        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        try:
            import jsonschema
            jsonschema.validate(report, schema)
        except ImportError:
            required = {"schema_version", "assessment", "device", "audit", "summary", "checks"}
            if not required.issubset(report):
                raise ValueError("Report does not satisfy minimum schema requirements")
            if report["summary"]["total_checks"] != len(report["checks"]):
                raise ValueError("Report summary total_checks does not match checks array")
        except Exception as exc:
            raise ValueError(f"Report schema validation failed: {exc}") from exc
