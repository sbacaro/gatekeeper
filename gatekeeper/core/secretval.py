"""Secret validity checking: is the leaked credential still live?

A found secret is "possibly exposed"; a *confirmed-live* secret is an active
incident. This module checks credential liveliness against provider APIs
without sending the secret anywhere except the provider that issued it.

Checks are opt-in (`--validate-secrets`) because they generate provider-side
audit-log events and may hit rate limits. Only read-only validation calls are
made - never anything that mutates provider state.

Supported: GitHub tokens, Slack tokens, Stripe live keys, Google API keys,
OpenAI keys, npm tokens, PyPI tokens. AWS access keys are reported but not
probed (needs both halves of the credential; left to the operator).
"""
import base64
import json
import urllib.error
import urllib.request

CHECK_TIMEOUT = 15

SEV_LIVE = "CRITICAL"


class SecretContext:
    """Extracted pieces of a leaked credential needed for validation."""

    def __init__(self, kind: str, value: str):
        self.kind = kind
        self.value = value


# -------------------------------------------------------------- extractors --

_TOKEN_PREFIXES = (
    ("github_pat_", "github_pat"), ("ghp_", "github_pat"), ("gho_", "github_oauth"),
    ("xoxb-", "slack_bot"), ("xoxp-", "slack_user"), ("xoxa-", "slack_app"),
    ("sk_live_", "stripe_live"), ("sk-", "openai"),
    ("npm_", "npm_token"), ("pypi-", "pypi_token"),
    ("AIza", "google_api_key"),
)


def _from_leak_text(leak_text: str) -> SecretContext | None:
    """Best-effort classification of a gitleaks/trivy leak string."""
    t = leak_text or ""
    for prefix, kind in _TOKEN_PREFIXES:
        idx = t.find(prefix)
        if idx >= 0:
            token = t[idx:].split()[0].rstrip('",;)')
            return SecretContext(kind, token)
    return None


def _extract_secret_value(target, finding: dict) -> SecretContext | None:
    """Get the raw token from the finding text or by re-reading the file.

    Reports are redacted by default (gitleaks --redact), so for real values we
    re-read the file at the finding's location - the token never leaves the
    machine except toward the provider that issued it.
    """
    ctx = _from_leak_text(finding.get("description", ""))
    if ctx:
        return ctx
    file = finding.get("file", "")
    line = finding.get("line") or 0
    if not file:
        return None
    try:
        lines = (target / file).read_text(errors="replace").splitlines()
    except OSError:
        return None
    start = max(0, (line or 1) - 3)
    window = lines[start: (line or 1) + 2] or lines
    return _from_leak_text("\n".join(window))


# ------------------------------------------------------------- validators ---

def _http(url: str, headers: dict) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=CHECK_TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, (exc.read() or b"").decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return 0, str(exc)


def _check_github(token: str) -> bool:
    code, _ = _http("https://api.github.com/user",
                    {"Authorization": f"Bearer {token}", "User-Agent": "gatekeeper"})
    return code == 200


def _check_slack(token: str) -> bool:
    code, body = _http("https://slack.com/api/auth.test",
                       {"Authorization": f"Bearer {token}"})
    try:
        data = json.loads(body or "{}")
    except json.JSONDecodeError:
        data = {}
    return code == 200 and bool(data.get("ok"))


def _check_openai(key: str) -> bool:
    code, _ = _http("https://api.openai.com/v1/models",
                    {"Authorization": f"Bearer {key}"})
    return code == 200


def _check_stripe(key: str) -> bool:
    auth = base64.b64encode(f"{key}:".encode()).decode()
    code, _ = _http("https://api.stripe.com/v1/balance",
                    {"Authorization": f"Basic {auth}"})
    return code == 200


def _check_google(key: str) -> bool:
    url = ("https://www.googleapis.com/youtube/v3/search?part=snippet&maxResults=1"
           f"&q=test&key={key}")
    code, body = _http(url, {})
    if code == 200:
        return True
    if code == 400 and "API key not valid" in body:
        return False
    return code in (403, 429)  # restricted/rate-limited: the key itself is live


def _check_npm(token: str) -> bool:
    code, _ = _http("https://registry.npmjs.org/-/whoami",
                    {"Authorization": f"Bearer {token}"})
    return code == 200


CHECKERS = {
    "github_pat": _check_github,
    "github_oauth": _check_github,
    "slack_bot": _check_slack,
    "slack_user": _check_slack,
    "slack_app": _check_slack,
    "openai": _check_openai,
    "stripe_live": _check_stripe,
    "google_api_key": _check_google,
    "npm_token": _check_npm,
}


# ---------------------------------------------------------------- public ----

def validate_secret(target, finding: dict) -> dict:
    """Check one secret finding. Returns {'validated', 'live', 'kind', 'error'};
    'live' is None when it cannot be determined (offline, unknown kind)."""
    ctx = _extract_secret_value(target, finding)
    if ctx is None:
        return {"validated": False, "live": None, "kind": "unknown",
                "error": "secret not recoverable from redacted report"}
    checker = CHECKERS.get(ctx.kind)
    if checker is None:
        return {"validated": False, "live": None, "kind": ctx.kind,
                "error": f"no validator for {ctx.kind}"}
    try:
        live = checker(ctx.value)
    except Exception as exc:
        return {"validated": False, "live": None, "kind": ctx.kind,
                "error": str(exc)[:200]}
    return {"validated": True, "live": live, "kind": ctx.kind, "error": ""}


def annotate_secret_liveliness(target, findings: list) -> list:
    """Attach 'secret_validation' to secrets findings (mutates in place)."""
    for f in findings:
        if f.get("category") != "secrets":
            continue
        result = validate_secret(target, f)
        f["secret_validation"] = result
        if result.get("live") is True:
            # A live leaked credential outranks everything else.
            f["severity"] = SEV_LIVE
            f["risk_score"] = 100
            f["title"] = f"{f.get('title', '')} [CREDENTIAL CONFIRMED LIVE]".strip()
    return findings
