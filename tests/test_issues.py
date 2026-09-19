from gatekeeper.core import issues


class TestIssueKey:
    def test_different_lines_differ(self, make_finding):
        a = issues.issue_key(make_finding(line=10), "/repo")
        b = issues.issue_key(make_finding(line=99), "/repo")
        assert a != b

    def test_line_ignored_by_fingerprint_diff(self, make_finding):
        # diffscan.fingerprint_key is the line-independent identity used in CI
        from gatekeeper.core.diffscan import fingerprint_key
        a = fingerprint_key(make_finding(line=10, fingerprint="t:c:f:10:x"))
        b = fingerprint_key(make_finding(line=99, fingerprint="t:c:f:99:x"))
        assert a == b == "t:c:f:x"

    def test_relative_paths_match(self, tmp_path, make_finding):
        a = issues.issue_key(make_finding(file="/repo/app.py"), "/repo")
        b = issues.issue_key(make_finding(file="app.py"), "/repo")
        assert a == b

    def test_different_titles_differ(self, make_finding):
        assert issues.issue_key(make_finding(title="A")) != \
            issues.issue_key(make_finding(title="B"))


class TestTriageState:
    def test_ignore_and_unignore(self, tmp_path, make_finding):
        f = make_finding()
        issues.apply_action(tmp_path, f, "ignore", reason="accepted")
        annotated, _ = issues.annotate_findings(tmp_path, [dict(f)])
        assert annotated[0]["status"] == "ignored"
        assert annotated[0]["reason"] == "accepted"

        issues.apply_action(tmp_path, f, "unignore")
        annotated, _ = issues.annotate_findings(tmp_path, [dict(f)])
        assert annotated[0]["status"] in ("open", "new")

    def test_snooze_of_zero_days_does_not_stick(self, tmp_path, make_finding):
        f = make_finding()
        issues.apply_action(tmp_path, f, "snooze", days=0)
        annotated, _ = issues.annotate_findings(tmp_path, [dict(f)])
        assert annotated[0]["status"] in ("open", "new")

    def test_severity_override(self, tmp_path, make_finding):
        f = make_finding(severity="LOW")
        issues.apply_action(tmp_path, f, "severity", severity="CRITICAL")
        annotated, _ = issues.annotate_findings(tmp_path, [dict(f)])
        assert annotated[0]["severity"] == "CRITICAL"

    def test_history_audit_trail(self, tmp_path, make_finding):
        f = make_finding()
        issues.apply_action(tmp_path, f, "ignore", reason="r1")
        issues.apply_action(tmp_path, f, "unignore")
        hist = issues.issue_history(tmp_path, f)
        assert [h["action"] for h in hist] == ["ignore", "unignore"]

    def test_disappeared_issue_auto_solves(self, tmp_path, make_finding):
        f = make_finding()
        issues.sync_seen(tmp_path, issues.annotate_findings(tmp_path, [dict(f)])[0])
        issues.annotate_findings(tmp_path, [])
        state = issues.load_state(tmp_path)
        solved = [e for e in state["issues"].values() if e.get("auto_solved")]
        assert len(solved) == 1


class TestGroupFindings:
    def test_same_cve_grouped(self, tmp_path, make_finding):
        findings = [
            make_finding(category="sca", title="CVE-2021-44228 in log4j@2.0",
                         file="pom.xml", id="A"),
            make_finding(category="sca", title="CVE-2021-44228 in log4j@2.0",
                         file="pom.xml", id="B"),
        ]
        annotated, _ = issues.annotate_findings(tmp_path, findings)
        groups = issues.group_findings(annotated)
        sizes = [g.get("group_size", 1) for g in groups]
        assert 2 in sizes

    def test_ignored_findings_stay_solo(self, tmp_path, make_finding):
        findings = [
            make_finding(category="secrets", title="Secret: K", file="a.py"),
            make_finding(category="secrets", title="Secret: K", file="b.py"),
        ]
        issues.apply_action(tmp_path, findings[0], "ignore")
        annotated, _ = issues.annotate_findings(tmp_path, findings)
        groups = issues.group_findings(annotated)
        assert len(groups) >= 2


class TestEstimateFixTime:
    def test_sca_is_fast(self, make_finding):
        assert issues.estimate_fix_time(make_finding(category="sca")) == "5 min"

    def test_injection_is_hard(self, make_finding):
        assert issues.estimate_fix_time(
            make_finding(category="sast", title="SQL Injection")) == "6 hr"


class TestConfigErrors:
    def test_missing_lockfile_detected(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        errors = issues.config_errors(tmp_path)
        assert any(e["title"] == "Missing lockfile" for e in errors)

    def test_swift_resolved_counts_as_lockfile(self, tmp_path):
        (tmp_path / "Package.swift").write_text("// swift")
        (tmp_path / "Package.resolved").write_text("{}")
        assert issues.config_errors(tmp_path) == []

    def test_gitignored_lockfile_still_missing(self, tmp_path):
        # A lockfile listed in .gitignore is not committed, so the "missing
        # lockfile" warning must still fire.
        (tmp_path / "Package.swift").write_text("// swift")
        (tmp_path / "Package.resolved").write_text("{}")
        (tmp_path / ".gitignore").write_text("Package.resolved\n")
        errors = issues.config_errors(tmp_path)
        assert any(e["title"] == "Missing lockfile" for e in errors)

    def test_no_pre_commit_noise(self, tmp_path):
        # A plain git repo without hooks must NOT generate any warning.
        (tmp_path / ".git").mkdir()
        (tmp_path / "go.mod").write_text("module x")
        (tmp_path / "go.sum").write_text("")
        assert issues.config_errors(tmp_path) == []

    def test_env_not_gitignored(self, tmp_path):
        (tmp_path / ".env").write_text("X=1")
        errors = issues.config_errors(tmp_path)
        assert any(".env not gitignored" in e["title"] for e in errors)

    def test_gitignored_env_is_fine(self, tmp_path):
        (tmp_path / ".env").write_text("X=1")
        (tmp_path / ".gitignore").write_text(".env\n")
        errors = issues.config_errors(tmp_path)
        assert not any(".env not gitignored" in e["title"] for e in errors)
