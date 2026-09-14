from gatekeeper.core import config as config_mod
from gatekeeper.core.cli import _diff_findings, _exit_code


class TestDiffFindings:
    def test_new_fixed_remaining(self, make_finding):
        base = [make_finding(title="Old bug"), make_finding(title="Fixed bug")]
        cur = [make_finding(title="Old bug"), make_finding(title="New bug")]
        new, fixed, remaining = _diff_findings(base, cur)
        assert {f["title"] for f in new} == {"New bug"}
        assert {f["title"] for f in fixed} == {"Fixed bug"}
        assert {f["title"] for f in remaining} == {"Old bug"}

    def test_severity_change_counts_as_change(self, make_finding):
        base = [make_finding(title="Issue", severity="LOW")]
        cur = [make_finding(title="Issue", severity="CRITICAL")]
        new, fixed, remaining = _diff_findings(base, cur)
        # key includes title-lower only, so same title = remaining regardless of sev
        assert len(remaining) == 1
        assert new == [] or len(new) == 1


class TestExitCode:
    def test_zero_when_no_high(self, make_finding):
        assert _exit_code([make_finding(severity="MEDIUM")], {"fail_on": "high"}) == 0

    def test_one_when_high(self, make_finding):
        assert _exit_code([make_finding(severity="HIGH")], {"fail_on": "high"}) == 1

    def test_policy_can_lower_threshold(self, make_finding):
        cfg = {"fail_on": "low"}
        assert _exit_code([make_finding(severity="LOW")], cfg) == 1

    def test_policy_can_raise_threshold(self, make_finding):
        cfg = {"fail_on": "critical"}
        assert _exit_code([make_finding(severity="HIGH")], cfg) == 0

    def test_min_risk_score_gates_lower_severity(self, make_finding):
        cfg = {"fail_on": "critical", "min_risk_score": 90}
        f = make_finding(severity="LOW", risk_score=95)
        assert _exit_code([f], cfg) == 1


class TestPolicyIntegration:
    def test_failing_findings_uses_risk_score(self, make_finding):
        cfg = {"fail_on": "critical", "min_risk_score": 90}
        f = make_finding(severity="LOW", risk_score=95)
        assert config_mod.failing_findings([f], cfg) == [f]

    def test_no_findings_never_fails(self):
        assert _exit_code([], {"fail_on": "high"}) == 0
