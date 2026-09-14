import pytest

from gatekeeper.core.config import (
    failing_findings,
    filter_findings,
    finding_ignored,
    load_config,
    parse_simple_yaml,
    severity_meets,
)

# ------------------------------------------------------------ YAML subset ---

class TestParseSimpleYaml:
    def test_scalars(self):
        text = """
fail_on: critical
min_risk_score: 80
validate_secrets: true
disabled: false
nothing: null
ratio: 0.5
name: "quoted value"
"""
        data = parse_simple_yaml(text)
        assert data["fail_on"] == "critical"
        assert data["min_risk_score"] == 80
        assert data["validate_secrets"] is True
        assert data["disabled"] is False
        assert data["nothing"] is None
        assert data["ratio"] == 0.5
        assert data["name"] == "quoted value"

    def test_nested_map(self):
        text = """
notifications:
  slack: https://hooks.example.com/x
  min_severity: high
"""
        data = parse_simple_yaml(text)
        assert data["notifications"] == {"slack": "https://hooks.example.com/x",
                                         "min_severity": "high"}

    def test_list_of_strings(self):
        text = """
ignore_paths:
  - tests/fixtures/
  - vendor/
"""
        assert parse_simple_yaml(text)["ignore_paths"] == ["tests/fixtures/", "vendor/"]

    def test_list_of_maps(self):
        text = """
ignore:
  - title: "Hardcoded JWT secret"
    reason: "test fixture"
  - fingerprint: "semgrep:secrets:x:1:jwt"
"""
        data = parse_simple_yaml(text)
        assert data["ignore"][0] == {"title": "Hardcoded JWT secret",
                                     "reason": "test fixture"}
        assert data["ignore"][1] == {"fingerprint": "semgrep:secrets:x:1:jwt"}

    def test_inline_list_syntax(self):
        assert parse_simple_yaml("tools: [semgrep, trivy]")["tools"] == \
            ["semgrep", "trivy"]

    def test_comments_and_blanks(self):
        text = """
# top comment
fail_on: high   # trailing comment
# url: http://not-a-comment '# tricky
"""
        data = parse_simple_yaml(text)
        assert data["fail_on"] == "high"
        assert "url" not in data

    def test_hash_inside_quotes_kept(self):
        data = parse_simple_yaml('title: "a # b"')
        assert data["title"] == "a # b"


# --------------------------------------------------------------- loading ----

class TestLoadConfig:
    def test_defaults_when_missing(self, tmp_path):
        cfg = load_config(tmp_path)
        assert cfg["fail_on"] == "high"
        assert cfg["tools"] is None
        assert cfg["ignore"] == []

    def test_loads_from_target(self, tmp_path):
        (tmp_path / "gatekeeper.yml").write_text("fail_on: medium\n")
        assert load_config(tmp_path)["fail_on"] == "medium"

    def test_yaml_extension_fallback(self, tmp_path):
        (tmp_path / "gatekeeper.yaml").write_text("min_risk_score: 70\n")
        assert load_config(tmp_path)["min_risk_score"] == 70

    def test_explicit_path_wins(self, tmp_path):
        (tmp_path / "gatekeeper.yml").write_text("fail_on: low\n")
        other = tmp_path / "other.yml"
        other.write_text("fail_on: critical\n")
        assert load_config(tmp_path, path=other)["fail_on"] == "critical"

    def test_unknown_keys_ignored(self, tmp_path):
        (tmp_path / "gatekeeper.yml").write_text("fail_on: low\nhax: yes\n")
        cfg = load_config(tmp_path)
        assert "hax" not in cfg

    def test_broken_file_falls_back_to_defaults(self, tmp_path):
        (tmp_path / "gatekeeper.yml").write_text("fail_on: high\n:\n:\nbad")
        cfg = load_config(tmp_path)
        assert cfg["fail_on"] == "high"


# ----------------------------------------------------------------- policy ---

class TestSeverityMeets:
    @pytest.mark.parametrize("sev,thr,expected", [
        ("CRITICAL", "high", True),
        ("HIGH", "high", True),
        ("MEDIUM", "high", False),
        ("LOW", "info", True),
        ("critical", "CRITICAL", True),
        ("", "high", False),
        ("garbage", "high", False),
    ])
    def test_matrix(self, sev, thr, expected):
        assert severity_meets(sev, thr) is expected


class TestFailingFindings:
    def test_default_threshold_is_high(self, make_finding):
        cfg = load_config(None)
        findings = [make_finding(severity="HIGH"), make_finding(severity="MEDIUM")]
        blocked = failing_findings(findings, cfg)
        assert len(blocked) == 1
        assert blocked[0]["severity"] == "HIGH"

    def test_configurable_threshold(self, make_finding):
        cfg = {"fail_on": "critical"}
        findings = [make_finding(severity="HIGH"), make_finding(severity="CRITICAL")]
        assert len(failing_findings(findings, cfg)) == 1

    def test_min_risk_score_gates_medium(self, make_finding):
        cfg = {"fail_on": "critical", "min_risk_score": 80}
        findings = [make_finding(severity="MEDIUM", risk_score=85),
                    make_finding(severity="MEDIUM", risk_score=40)]
        blocked = failing_findings(findings, cfg)
        assert len(blocked) == 1
        assert blocked[0]["risk_score"] == 85

    def test_fail_on_none_disables_gate(self, make_finding):
        cfg = {"fail_on": "none"}
        assert failing_findings([make_finding(severity="CRITICAL")], cfg) == []


# ---------------------------------------------------------------- ignores ---

class TestFindingIgnored:
    def test_ignore_paths_prefix(self, make_finding):
        cfg = {"ignore_paths": ["tests/fixtures"]}
        assert finding_ignored(make_finding(file="tests/fixtures/x.py"), cfg)
        assert finding_ignored(make_finding(file="tests/fixtures/sub/y.py"), cfg)
        assert not finding_ignored(make_finding(file="tests/test_x.py"), cfg)

    def test_ignore_by_title_case_insensitive(self, make_finding):
        cfg = {"ignore": [{"title": "SQL Injection"}]}
        assert finding_ignored(make_finding(title="sql injection"), cfg)

    def test_ignore_by_fingerprint_prefix(self, make_finding):
        cfg = {"ignore": [{"fingerprint": "semgrep:sast:app.py:10"}]}
        assert finding_ignored(make_finding(), cfg)
        other = make_finding(file="other.py")
        assert not finding_ignored(other, cfg)

    def test_plain_string_ignore_matches_title(self, make_finding):
        cfg = {"ignore": ["sql injection"]}
        assert finding_ignored(make_finding(), cfg)

    def test_no_match(self, make_finding):
        cfg = {"ignore_paths": ["vendor"], "ignore": [{"title": "Other"}]}
        assert not finding_ignored(make_finding(), cfg)


class TestFilterFindings:
    def test_filter(self, make_finding):
        cfg = {"ignore_paths": ["vendor"]}
        findings = [make_finding(file="app.py"), make_finding(file="vendor/lib.py")]
        kept = filter_findings(findings, cfg)
        assert [f["file"] for f in kept] == ["app.py"]
