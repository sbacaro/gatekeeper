"""Shared fixtures: tiny Finding dicts used across the test suite."""
import pytest


@pytest.fixture
def make_finding():
    def _make(**kw):
        base = {
            "id": "F-1",
            "severity": "HIGH",
            "tool": "semgrep",
            "category": "sast",
            "file": "app.py",
            "line": 10,
            "title": "SQL Injection",
            "description": "User input flows into a SQL query",
            "remediation_hint": "Use parameterized queries",
            "risk_score": 60,
        }
        base.update(kw)
        base.setdefault("fingerprint",
                        f"{base['tool']}:{base['category']}:{base['file']}:"
                        f"{base['line']}:{base['title'].lower().replace(' ', '-')}")
        return base
    return _make
