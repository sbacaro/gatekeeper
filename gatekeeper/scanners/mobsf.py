"""MobSF integration via its REST API: upload an iOS/Android source tree as a
tarball, trigger static analysis and pull the JSON report.

Requires Docker; the MobSF container is started on demand and removed after.
"""
import io
import json
import os
import shutil
import subprocess
import tarfile
import time
import uuid
from pathlib import Path

from gatekeeper.core.detect import SKIP_DIRS

MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_PORT = 18080
MOBSF_KEY_ENV = "MOBSF_GATEKEEPER_KEY"
CONTAINER_PREFIX = "gatekeeper-mobsf"


class MobsfError(RuntimeError):
    pass


def _has_mobile_sources(target: Path) -> bool:
    markers = ("*.xcodeproj", "*.xcworkspace", "Podfile", "Cartfile",
               "*.pbxproj", "Info.plist", "build.gradle", "settings.gradle",
               "AndroidManifest.xml")
    for m in markers:
        if "*" in m:
            if list(target.rglob(m)):
                return True
        elif (target / m).exists():
            return True
    # .swift / .kt files alone also justify a MobSF pass
    return bool(list(target.rglob("*.swift")) or list(target.rglob("*.kt")))


def _make_tarball(target: Path, out_path: Path) -> None:
    def filter_fn(tarinfo):
        parts = Path(tarinfo.name).parts
        if any(p in SKIP_DIRS for p in parts):
            return None
        return tarinfo

    with tarfile.open(out_path, "w:gz") as tar:
        for entry in target.iterdir():
            if entry.name in SKIP_DIRS or entry.name.startswith("."):
                continue
            tar.add(entry, arcname=entry.name, filter=filter_fn)


def _container_name() -> str:
    return f"{CONTAINER_PREFIX}-{uuid.uuid4().hex[:8]}"


def _wait_for_mobsf(port: int, timeout: int = 120) -> None:
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=3) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(2)
    raise MobsfError("MobSF container did not become ready in time")


def _api_headers() -> dict:
    key = os.environ.get(MOBSF_KEY_ENV, "")
    if not key:
        raise MobsfError(
            f"Set {MOBSF_KEY_ENV} to the MobSF API key printed at container "
            "startup (default install prints it on first boot).")
    return {"Authorization": key}


def _post(url: str, headers: dict, data=None, files=None) -> dict:
    import urllib.error
    import urllib.request
    boundary = uuid.uuid4().hex
    body = io.BytesIO()
    for k, v in (data or {}).items():
        body.write(f"--{boundary}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
        body.write(f"{v}\r\n".encode())
    if files:
        fname, fcontent, ftype = files
        body.write(f"--{boundary}\r\n".encode())
        body.write(
            f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'.encode())
        body.write(f"Content-Type: {ftype}\r\n\r\n".encode())
        body.write(fcontent)
        body.write(b"\r\n")
    body.write(f"--{boundary}--\r\n".encode())
    payload = body.getvalue()
    headers = {**headers,
               "Content-Type": f"multipart/form-data; boundary={boundary}"}
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise MobsfError(f"MobSF API error {exc.code}: {exc.read()[:200]}") from exc
    except json.JSONDecodeError as exc:
        raise MobsfError("MobSF returned invalid JSON") from exc


def run_mobsf(target, raw_dir, progress_cb=None, **_) -> tuple:
    """Full MobSF static analysis of a mobile project via its REST API."""
    target = Path(target)
    if not shutil.which("docker"):
        return [], "skipped (docker not available for MobSF)"
    if not _has_mobile_sources(target):
        return [], None

    from scanners import _run, _save_raw  # reuse helpers

    name = _container_name()
    up, _ = _run(["docker", "run", "-d", "--rm",
                  "-p", f"{MOBSF_PORT}:8000",
                  "-e", "MOBSF_ANALYZER_MULTI_PROCESSING=1",
                  "--name", name, MOBSF_IMAGE], timeout=120)
    if up != 0:
        return [], "error: could not start MobSF container"

    try:
        _wait_for_mobsf(MOBSF_PORT)
        # Container prints its API key at startup; fetch from docker logs.
        _, logs, _ = _run(["docker", "logs", name], timeout=30)
        api_key = next((ln.split()[-1] for ln in logs.splitlines()
                        if "API Key" in ln or "apikey" in ln.lower()
                        and len(ln.split()[-1]) >= 32), None)
        if not api_key:
            return [], "error: could not read MobSF API key from container logs"
        os.environ.setdefault(MOBSF_KEY_ENV, api_key)
        headers = _api_headers()
        base = f"http://127.0.0.1:{MOBSF_PORT}/api/v1"

        tar_path = Path(raw_dir) / "mobsf-upload.tar.gz"
        _make_tarball(target, tar_path)

        upload = _post(f"{base}/upload/", headers,
                       files=("source.tar.gz", tar_path.read_bytes(), "application/gzip"))
        scan_hash = upload.get("hash")
        if not scan_hash:
            return [], "error: MobSF upload failed"

        scan_type = "apk" if list(target.rglob("*.kt")) or list(target.rglob("java")) \
            else "ios_source"
        _post(f"{base}/scan/", headers, data={"scan_type": scan_type, "hash": scan_hash})

        # Poll for completion
        for _ in range(60):
            time.sleep(5)
            report = _post(f"{base}/scan_json/", headers,
                           data={"hash": scan_hash})
            if report.get("scan_date"):
                break
        else:
            return [], "error: MobSF scan timed out"

        _save_raw(Path(raw_dir), "mobsf", report)
        findings = _mobsf_findings(report)
        return findings, None
    except MobsfError as exc:
        return [], f"error: {exc}"
    finally:
        subprocess.run(["docker", "stop", name], capture_output=True, timeout=60)


_SEV_MAP = {"high": "HIGH", "critical": "CRITICAL", "warning": "MEDIUM",
            "info": "LOW", "good": "INFO"}


def _mobsf_findings(report: dict) -> list:
    from scanners import _make_finding
    findings = []
    sections = [
        ("manifest_analysis", "Manifest"), ("code_analysis", "Code"),
        ("file_analysis", "File"), ("binary_analysis", "Binary"),
    ]
    for section, label in sections:
        items = report.get(section) or {}
        for item in (items.get("findings") or []):
            # MobSF items: [rule, severity, description, ...]
            if not isinstance(item, (list, tuple)) or len(item) < 3:
                continue
            rule, sev_raw, desc = item[0], str(item[1]).lower(), str(item[2])
            sev = _SEV_MAP.get(sev_raw, "MEDIUM")
            title = f"MobSF {label}: {rule}"
            findings.append(_make_finding(
                "mobsf", "sast", sev, report.get("file_name", ""), 0,
                title[:200], desc[:400],
                "Review the MobSF recommendation for this finding at the "
                "referenced location.",
            ))
    return findings
