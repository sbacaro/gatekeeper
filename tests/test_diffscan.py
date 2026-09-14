from gatekeeper.core.diffscan import (
    diff_findings,
    fingerprint_key,
    load_baseline,
    restrict_to_changed,
)


class TestFingerprintKey:
    def test_strips_line_from_fingerprint(self, make_finding):
        f = make_finding(fingerprint="semgrep:sast:app.py:10:sql")
        assert fingerprint_key(f) == "semgrep:sast:app.py:sql"

    def test_fallback_without_fingerprint(self, make_finding):
        f = make_finding(fingerprint="", category="sast", file="app.py",
                         title="SQL Injection")
        assert fingerprint_key(f) == "sast|app.py|sql injection"


class TestDiffFindings:
    def test_new_fixed_remaining(self, make_finding):
        base = [make_finding(title="Old"), make_finding(title="Fixed one")]
        cur = [make_finding(title="Old"), make_finding(title="Fresh")]
        d = diff_findings({"findings": base}, cur)
        assert {f["title"] for f in d["new"]} == {"Fresh"}
        assert {f["title"] for f in d["fixed"]} == {"Fixed one"}
        assert {f["title"] for f in d["remaining"]} == {"Old"}

    def test_line_drift_not_new(self, make_finding):
        base = [make_finding(line=5, title="T")]
        cur = [make_finding(line=99, title="T")]
        d = diff_findings({"findings": base}, cur)
        assert d["new"] == []
        assert len(d["remaining"]) == 1

    def test_fixed_when_absent_from_current(self, make_finding):
        base = [make_finding(title="Gone")]
        d = diff_findings({"findings": base}, [])
        assert len(d["fixed"]) == 1
        assert d["new"] == []


class TestRestrictToChanged:
    def test_keeps_only_changed_files(self, make_finding):
        findings = [make_finding(file="a.py"), make_finding(file="b.py")]
        out = restrict_to_changed(findings, ["a.py"])
        assert [f["file"] for f in out] == ["a.py"]

    def test_empty_changed_files_keeps_all(self, make_finding):
        findings = [make_finding(file="a.py")]
        assert restrict_to_changed(findings, []) == findings

    def test_sca_manifest_directory_match(self, make_finding):
        f = make_finding(category="sca", file="package-lock.json")
        out = restrict_to_changed([f], ["src/index.js", "package.json"])
        assert len(out) == 1

    def test_windows_paths_normalized(self, make_finding):
        f = make_finding(file="src\\a.py")
        out = restrict_to_changed([f], ["src/a.py"])
        assert len(out) == 1


class TestLoadBaseline:
    def test_valid_json(self, tmp_path):
        p = tmp_path / "summary.json"
        p.write_text('{"findings": []}')
        assert load_baseline(p) == {"findings": []}

    def test_invalid_json_returns_none(self, tmp_path):
        p = tmp_path / "summary.json"
        p.write_text("not json{")
        assert load_baseline(p) is None

    def test_missing_file_returns_none(self, tmp_path):
        assert load_baseline(tmp_path / "nope.json") is None
