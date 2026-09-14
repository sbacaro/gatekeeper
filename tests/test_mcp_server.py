"""Tests for the MCP server: tool discovery, handlers and JSON-RPC framing."""
import json
from unittest import mock

from gatekeeper.mcp import server


class TestToolCatalog:
    def test_all_expected_tools(self):
        names = {t["name"] for t in server.TOOLS}
        assert names == {
            "gatekeeper_scan", "gatekeeper_list", "gatekeeper_finding",
            "gatekeeper_triage", "gatekeeper_verify", "gatekeeper_plan",
            "gatekeeper_fix", "gatekeeper_ci", "gatekeeper_sarif",
            "gatekeeper_policy",
        }

    def test_every_tool_has_schema(self):
        for tool in server.TOOLS:
            assert tool["inputSchema"]["type"] == "object"
            assert tool["description"]


class TestHandlers:
    def test_list_without_scan(self):
        with mock.patch.object(server, "_latest_summary", return_value=None):
            out = server.tool_list({"path": "/repo"})
        assert "error" in out

    def test_finding_not_found(self, make_finding):
        with mock.patch.object(server, "_latest_summary",
                               return_value={"findings": []}):
            out = server.tool_finding({"path": "/repo", "id": "nope"})
        assert "not found" in out["error"]

    def test_finding_found_by_title(self, make_finding):
        summary = {"target": "/repo", "findings": [make_finding(title="Hardcoded Secret")]}
        with mock.patch.object(server, "_latest_summary", return_value=summary), \
             mock.patch.object(server.issues, "issue_history", return_value=[]):
            out = server.tool_finding({"path": "/repo", "id": "hardcoded"})
        assert out["title"] == "Hardcoded Secret"

    def test_triage_applies_action(self, make_finding):
        summary = {"target": "/repo", "findings": [make_finding(title="Bug")]}
        entry = {"ignored": True}
        with mock.patch.object(server, "_latest_summary", return_value=summary), \
             mock.patch.object(server.issues, "apply_action", return_value=entry) as act:
            out = server.tool_triage({"path": "/repo", "id": "bug",
                                      "action": "ignore", "reason": "ok"})
        assert out["ok"] is True
        act.assert_called_once()

    def test_policy_returns_effective_config(self, tmp_path):
        (tmp_path / "gatekeeper.yml").write_text("fail_on: critical\n")
        out = server.tool_policy({"path": str(tmp_path)})
        assert out["policy"]["fail_on"] == "critical"

    def test_policy_without_file(self, tmp_path):
        out = server.tool_policy({"path": str(tmp_path)})
        assert out["config_file"] is None
        assert out["policy"]["fail_on"] == "high"

    def test_ci_passes_when_no_findings(self, tmp_path):
        result = mock.MagicMock()
        result.to_dict.return_value = {"findings": []}
        with mock.patch("gatekeeper.core.cli._load_latest_baseline",
                        return_value=(None, None)), \
             mock.patch.object(server, "run_scan", return_value=(result, tmp_path)), \
             mock.patch("gatekeeper.core.cli._git_changed_files", return_value=[]):
            out = server.tool_ci({"path": str(tmp_path)})
        assert out["verdict"] == "PASSED"
        assert out["blocking"] == []


class TestJsonRpc:
    def test_initialize(self, capsys):
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        out = json.loads(capsys.readouterr().out)
        assert out["id"] == 1
        assert out["result"]["serverInfo"]["name"] == "gatekeeper"

    def test_tools_list(self, capsys):
        server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        out = json.loads(capsys.readouterr().out)
        assert len(out["result"]["tools"]) == 10

    def test_unknown_tool_is_error(self, capsys):
        server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "nope", "arguments": {}}})
        out = json.loads(capsys.readouterr().out)
        assert out["error"]["code"] == -32602

    def test_tool_call_roundtrip(self, capsys, tmp_path):
        empty = {"target": str(tmp_path), "findings": []}
        with mock.patch.object(server, "_latest_summary", return_value=empty):
            server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                           "params": {"name": "gatekeeper_list",
                                      "arguments": {"path": str(tmp_path)}}})
        out = json.loads(capsys.readouterr().out)
        assert out["id"] == 4
        inner = json.loads(out["result"]["content"][0]["text"])
        assert inner["total"] == 0

    def test_handler_exception_is_isError(self, capsys):
        with mock.patch.object(server, "tool_scan", side_effect=OSError("disk")):
            server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                           "params": {"name": "gatekeeper_scan",
                                      "arguments": {"path": "/x"}}})
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["isError"] is True

    def test_ping(self, capsys):
        server.handle({"jsonrpc": "2.0", "id": 6, "method": "ping"})
        out = json.loads(capsys.readouterr().out)
        assert out["result"] == {}

    def test_notification_gets_no_response(self, capsys):
        server.handle({"jsonrpc": "2.0",
                       "method": "notifications/initialized"})
        assert capsys.readouterr().out == ""
