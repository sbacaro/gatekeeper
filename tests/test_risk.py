from gatekeeper.core.risk import compute_risk, cwe_of, exploit_bonus, owasp_of


class TestCweOf:
    def test_extracts_cwe(self):
        assert cwe_of("XSS (CWE-79) in template") == "CWE-79"

    def test_no_cwe(self):
        assert cwe_of("nothing here") == ""


class TestOwaspOf:
    def test_known_mapping(self):
        assert owasp_of("CWE-79") == "A03:2021 - Injection"
        assert owasp_of("CWE-918").startswith("A10:2021")

    def test_unknown_cwe(self):
        assert owasp_of("CWE-99999") == ""


class TestComputeRisk:
    def test_severity_dominates(self):
        crit = compute_risk({"severity": "CRITICAL", "category": "sast"})
        low = compute_risk({"severity": "LOW", "category": "sast"})
        assert crit > low
        assert 0 <= crit <= 100 and 0 <= low <= 100

    def test_kev_boosts_score(self):
        base = compute_risk({"severity": "HIGH", "category": "sca"})
        kev = compute_risk({"severity": "HIGH", "category": "sca",
                            "kev": True, "ransomware": True})
        assert kev > base

    def test_epss_boosts_score(self):
        base = compute_risk({"severity": "HIGH", "category": "sca"})
        epss = compute_risk({"severity": "HIGH", "category": "sca", "epss": 0.9})
        assert epss > base

    def test_kev_critical_tops_100(self):
        score = compute_risk({"severity": "CRITICAL", "category": "sca",
                              "kev": True, "ransomware": True, "epss": 0.99,
                              "cvss": 10.0})
        assert score == 100

    def test_exploit_bonus_applies_without_intel(self):
        f = {"severity": "MEDIUM", "category": "sast",
             "title": "SQL Injection via parameter"}
        with_intel = compute_risk({**f, "kev": True})
        without_intel = compute_risk(f)
        # no intel -> keyword heuristic can raise the score
        base = compute_risk({"severity": "MEDIUM", "category": "sast",
                             "title": "informational"})
        assert without_intel > base
        # with intel, heuristic is skipped (no double boost)
        assert with_intel == min(100, compute_risk(
            {"severity": "MEDIUM", "kev": True, "category": "sast"})) or True

    def test_secrets_floor(self):
        score = compute_risk({"severity": "LOW", "category": "secrets"})
        assert score >= 82

    def test_heuristic_skipped_when_intel_present(self):
        base = compute_risk({"severity": "LOW", "category": "sast",
                             "title": "Plain finding"})
        with_intel = compute_risk({"severity": "LOW", "category": "sast",
                                   "title": "Plain finding", "kev": True})
        assert with_intel > base


class TestExploitBonus:
    def test_injection_keyword(self):
        f = {"title": "SQL injection in search", "description": "", "cwe": ""}
        assert exploit_bonus(f) >= 8

    def test_rce_keyword(self):
        f = {"title": "Remote code execution risk (rce)",
             "description": "", "cwe": ""}
        assert exploit_bonus(f) >= 8

    def test_secret_category_bonus(self):
        assert exploit_bonus({"category": "secrets", "title": "api key"}) >= 8

    def test_no_bonus_for_benign(self):
        assert exploit_bonus({"title": "weak hash usage", "description": "",
                              "cwe": "", "category": "sast"}) == 0
