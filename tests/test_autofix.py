from unittest import mock

import pytest

from gatekeeper.core import autofix


class TestParsePkg:
    @pytest.mark.parametrize("raw,name,ver", [
        ("lodash@4.17.21", "lodash", "4.17.21"),
        ("@babel/core@7.0.0", "@babel/core", "7.0.0"),
        ("lodash", "lodash", ""),
        ("@types/node", "@types/node", ""),
    ])
    def test_parse(self, raw, name, ver):
        assert autofix._parse_pkg(raw) == (name, ver)


class TestScaFindings:
    def test_only_fixable_sca(self, make_finding):
        summary = {"findings": [
            make_finding(category="sca", package="lodash@4.17.0",
                         remediation_hint="Upgrade lodash to 4.17.21"),
            make_finding(category="sast"),  # wrong category
            make_finding(category="sca", package="x@1", status="ignored",
                         remediation_hint="Upgrade x to 2"),
            make_finding(category="sca", package="y@1",
                         remediation_hint="no version given"),
        ]}
        fixes = autofix.sca_findings(summary, 10)
        assert len(fixes) == 1
        assert fixes[0]["name"] == "lodash"
        assert fixes[0]["fix"] == "4.17.21"

    def test_respects_max(self, make_finding):
        summary = {"findings": [
            make_finding(id=f"F{i}", category="sca", package=f"p{i}@1",
                         title=f"p{i} vuln",
                         remediation_hint=f"Upgrade p{i} to 2")
            for i in range(5)
        ]}
        assert len(autofix.sca_findings(summary, 2)) == 2


class TestFixedVersionParsing:
    @pytest.mark.parametrize("hint,expected", [
        ("Upgrade lodash to 4.17.21", "4.17.21"),
        ("suggested: 2.0.3", "2.0.3"),
        ("no version here", ""),
    ])
    def test_parsing(self, make_finding, hint, expected):
        assert autofix._fixed_version_from_finding(
            make_finding(remediation_hint=hint)) == expected


class TestApplyFixes:
    def _summary(self, make_finding, pkg="lodash@4.17.0"):
        return {"findings": [make_finding(
            category="sca", package=pkg, file="package-lock.json",
            remediation_hint="Upgrade lodash to 4.17.21")]}

    def test_js_ecosystem(self, tmp_path, make_finding):
        (tmp_path / "package.json").write_text("{}")
        with mock.patch.object(autofix, "_upgrade_js",
                               return_value=(True, "added")) as up:
            report = autofix.apply_fixes(str(tmp_path), self._summary(make_finding))
        assert report["applied"] and report["applied"][0]["ok"] is True
        up.assert_called_once_with(tmp_path, "lodash", "4.17.21")

    def test_python_ecosystem(self, tmp_path, make_finding):
        (tmp_path / "requirements.txt").write_text("requests==2.19.0\nflask>=2\n")
        summary = {"findings": [make_finding(
            category="sca", package="requests@2.19.0", file="requirements.txt",
            remediation_hint="Upgrade requests to 2.31.0")]}
        with mock.patch.object(autofix, "_upgrade_python",
                               return_value=(True, "pinned")) as up:
            report = autofix.apply_fixes(str(tmp_path), summary)
        assert report["applied"][0]["package"] == "requests@2.31.0"
        assert report["applied"][0]["ok"] is True
        up.assert_called_once_with(tmp_path, "requests", "2.31.0")

    def test_unsupported_ecosystem_fails_gracefully(self, tmp_path, make_finding):
        f = make_finding(category="sca", package="golang.org/x/net@0.1",
                         file="go.mod", remediation_hint="Upgrade x/net to 0.17")
        report = autofix.apply_fixes(str(tmp_path), {"findings": [f]})
        assert report["failed"][0]["note"] == "unsupported ecosystem for autofix"

    def test_never_raises_on_bad_input(self, tmp_path):
        report = autofix.apply_fixes(str(tmp_path), {"findings": [{"oops": 1}]})
        assert report == {"applied": [], "failed": []}


class TestUpgradePython:
    def test_pin_in_requirements(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\nrequests==2.19.0\nflask>=2\n")
        ok, note = autofix._upgrade_python(tmp_path, "requests", "2.31.0")
        assert ok
        content = req.read_text()
        assert "requests==2.31.0" in content
        assert "# comment" in content
        assert "flask>=2" in content

    def test_package_not_found(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask>=2\n")
        ok, note = autofix._upgrade_python(tmp_path, "requests", "2.31.0")
        assert not ok


class TestUpgradeJs:
    def test_picks_npm_by_default(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        with mock.patch.object(autofix, "_run", return_value=(0, "ok", "")) as run:
            ok, _ = autofix._upgrade_js(tmp_path, "lodash", "4.17.21")
        assert ok
        assert run.call_args[0][0][:2] == ["npm", "install"]

    def test_picks_pnpm(self, tmp_path):
        (tmp_path / "pnpm-lock.yaml").write_text("")
        with mock.patch.object(autofix, "_run", return_value=(0, "ok", "")) as run:
            ok, _ = autofix._upgrade_js(tmp_path, "lodash", "4.17.21")
        assert ok
        assert run.call_args[0][0][:2] == ["pnpm", "add"]

    def test_reports_failure(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        with mock.patch.object(autofix, "_run",
                               return_value=(1, "", "ERR! broken")):
            ok, note = autofix._upgrade_js(tmp_path, "lodash", "4.17.21")
        assert not ok
        assert "broken" in note or "ERR" in note
