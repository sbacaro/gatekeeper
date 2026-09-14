import urllib.error
from unittest import mock

from gatekeeper.core import notify


def _http_ok(resp_status=200):
    resp = mock.MagicMock()
    resp.status = resp_status
    resp.__enter__ = mock.MagicMock(return_value=resp)
    resp.__exit__ = mock.MagicMock(return_value=False)
    return resp


class TestPost:
    def test_success(self):
        with mock.patch("urllib.request.urlopen", return_value=_http_ok(200)):
            ok, detail = notify._post("https://example.com/hook", {"a": 1})
        assert ok is True
        assert "200" in detail

    def test_http_error(self):
        err = urllib.error.HTTPError("url", 500, "boom", None, None)
        with mock.patch("urllib.request.urlopen", side_effect=err):
            ok, detail = notify._post("https://example.com/hook", {})
        assert ok is False
        assert "500" in detail

    def test_network_error(self):
        with mock.patch("urllib.request.urlopen",
                        side_effect=urllib.error.URLError("no dns")):
            ok, _ = notify._post("https://example.com/hook", {})
        assert ok is False


class TestNotifyScanResult:
    CFG = {"notifications": {
        "slack": "https://hooks.slack.com/services/x",
        "webhook": "https://example.com/hook",
    }}

    def test_sends_to_both_channels(self, make_finding):
        with mock.patch.object(notify, "_post", return_value=(True, "HTTP 200")) as post:
            report = notify.notify_scan_result(
                "/repo", "FAILED", [make_finding(severity="CRITICAL")], self.CFG)
        assert report["slack"]["ok"] is True
        assert report["webhook"]["ok"] is True
        assert post.call_count == 2

    def test_passed_and_no_on_pass_skips(self, make_finding):
        with mock.patch.object(notify, "_post") as post:
            report = notify.notify_scan_result("/repo", "PASSED", [], self.CFG)
        assert report == {}
        post.assert_not_called()

    def test_passed_with_on_pass_notifies(self, make_finding):
        cfg = {"notifications": {"webhook": "https://x", "on_pass": True}}
        with mock.patch.object(notify, "_post", return_value=(True, "HTTP 200")):
            report = notify.notify_scan_result("/repo", "PASSED", [], cfg)
        assert report["webhook"]["ok"] is True

    def test_min_severity_filters(self, make_finding):
        cfg = {"notifications": {"webhook": "https://x", "min_severity": "critical"}}
        findings = [make_finding(severity="HIGH"), make_finding(severity="CRITICAL")]
        with mock.patch.object(notify, "_post", return_value=(True, "HTTP 200")) as post:
            notify.notify_scan_result("/repo", "FAILED", findings, cfg)
        payload = post.call_args[0][1]
        assert len(payload["findings"]) == 1
        assert payload["findings"][0]["severity"] == "CRITICAL"

    def test_post_exception_never_raises(self, make_finding):
        with mock.patch.object(notify, "_post", side_effect=RuntimeError("boom")):
            report = notify.notify_scan_result("/repo", "FAILED",
                                               [make_finding()], self.CFG)
        assert report["slack"]["ok"] is False
        assert report["webhook"]["ok"] is False

    def test_no_notifications_configured(self, make_finding):
        assert notify.notify_scan_result("/repo", "FAILED",
                                         [make_finding()], {}) == {}

    def test_webhook_payload_shape(self, make_finding):
        cfg = {"notifications": {"webhook": "https://x"}}
        f = make_finding(severity="CRITICAL", risk_score=100)
        with mock.patch.object(notify, "_post", return_value=(True, "HTTP 200")) as post:
            notify.notify_scan_result("/repo", "FAILED", [f], cfg)
        payload = post.call_args[0][1]
        assert payload["verdict"] == "FAILED"
        assert payload["target"] == "/repo"
        assert payload["counts"]["CRITICAL"] == 1
        assert payload["findings"][0]["risk_score"] == 100


class TestSlackBlocks:
    def test_structure(self, make_finding):
        payload = notify.slack_blocks("/repo", "FAILED",
                                      [make_finding() for _ in range(12)], {})
        assert "Gatekeeper FAILED" in payload["text"]
        attachment = payload["attachments"][0]
        assert attachment["color"] == "danger"
        section = attachment["blocks"][0]["text"]["text"]
        assert "...and 2 more_" in section

    def test_pass_is_green(self, make_finding):
        payload = notify.slack_blocks("/repo", "PASSED", [], {})
        assert payload["attachments"][0]["color"] == "good"
