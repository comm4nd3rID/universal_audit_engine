
import collections
import json
from pathlib import Path

from universal_audit.audit.normalizer import normalize
from universal_audit.audit.parser import AuditParser
from universal_audit.audit.variables import resolve_variables


ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = ROOT / "audit_profiles"
GOLDEN = json.loads((ROOT / "tests" / "golden" / "audit_counts.json").read_text(encoding="utf-8"))


def test_all_six_audits_match_golden_counts():
    for filename, expected in GOLDEN.items():
        parsed = AuditParser().parse_file(AUDIT_DIR / filename)
        canonical = normalize(parsed)
        resolve_variables(canonical, {})
        checks = list(canonical.iter_checks())
        types = collections.Counter(check.canonical_check_type for check in checks)
        assert len(checks) == expected["checks"], filename
        assert dict(types) == expected["types"], filename
        assert canonical.metadata["spec"]["profile"] in {"L1", "L2"}
        assert len(canonical.file_hash) == 64
        assert all(check.check_id for check in checks)
        assert len({check.check_id for check in checks}) == len(checks)


def test_metadata_and_variables_are_extracted():
    parsed = AuditParser().parse_file(AUDIT_DIR / "CIS_Cisco_IOS_XE_17.x_v2.2.1_L1.audit")
    assert parsed.syntax_family == "Cisco"
    assert parsed.metadata["spec"]["name"] == "Cisco IOS XE 17.x"
    assert parsed.metadata["spec"]["version"] == "2.2.1"
    assert len(parsed.variables) == 19


def test_multiline_fields_preserve_structural_looking_banner_marker():
    parsed = AuditParser().parse_file(AUDIT_DIR / "CIS_Cisco_IOS_XE_17.x_v2.2.1_L1.audit")
    canonical = normalize(parsed)
    banner = next(c for c in canonical.iter_checks() if c.canonical_check_type == "CISCO_BANNER_CHECK")
    assert "<banner-text>" in banner.parameters["solution"]


def test_variables_resolve_without_missing_values():
    parsed = AuditParser().parse_file(AUDIT_DIR / "CIS_FortiGate_7.4.x_v1.0.1_L1.audit")
    canonical = normalize(parsed)
    resolve_variables(canonical, {})
    assert all(not check.missing_variables for check in canonical.iter_checks())
    dns = next(c for c in canonical.iter_checks() if c.description == "dns server 1")
    assert "10.0.0.1" in dns.parameters["expect"]

def test_audit_string_escape_decodes_backslash_for_regex():
    source = r'''
<check_type:"Cisco">
  <item>
    type : CONFIG_CHECK
    description : "Escaped regex"
    item : "^deny ip 10\\.0\\.0\\.1$"
  </item>
</check_type>
'''
    parsed = AuditParser().parse_text(source)
    canonical = normalize(parsed)
    check = next(canonical.iter_checks())
    assert check.parameters["item"] == r"^deny ip 10\.0\.0\.1$"
