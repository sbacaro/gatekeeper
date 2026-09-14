"""Stack detection for a target directory."""
import os
from pathlib import Path

SWIFT_MARKERS = {"Package.swift", "Podfile", "Cartfile", "Cartfile.resolved"}
SWIFT_DIR_SUFFIXES = (".xcodeproj", ".xcworkspace")
JS_MARKERS = {"package.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}
PY_MARKERS = {
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "poetry.lock",
}
IAC_MARKERS = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}
IAC_SUFFIXES = (".tf", ".tfvars")
GO_MARKERS = {"go.mod", "go.sum"}

SKIP_DIRS = {
    ".git", "node_modules", "reports", ".build", "DerivedData", "Pods",
    "__pycache__", ".venv", "venv", "dist", "build", ".next", ".cache",
}

MAX_DEPTH = 6


def walk_files(root: Path, max_depth: int = MAX_DEPTH):
    root = root.resolve()
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        depth = len(Path(dirpath).parts) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        for filename in filenames:
            yield Path(dirpath) / filename


def inventory(target: Path) -> dict:
    """Fast file inventory used for scan scope + progress baselines."""
    total_files = 0
    total_bytes = 0
    by_ext = {}
    for path in walk_files(target):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        total_files += 1
        total_bytes += size
        ext = path.suffix.lower() or "(none)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
    return {"total_files": total_files, "total_bytes": total_bytes, "by_ext": by_ext}


def detect_stacks(target: Path) -> dict:
    """Return a dict of stack names to booleans for the given target directory."""
    stacks = {"swift": False, "javascript": False, "python": False, "go": False, "iac": False}
    files = list(walk_files(target))
    suffixes = set()

    for path in files:
        name = path.name
        suffixes.add(path.suffix)
        if name in SWIFT_MARKERS or name.endswith(SWIFT_DIR_SUFFIXES):
            stacks["swift"] = True
        if name in JS_MARKERS:
            stacks["javascript"] = True
        if name in PY_MARKERS:
            stacks["python"] = True
        if name in GO_MARKERS:
            stacks["go"] = True
        if name in IAC_MARKERS or name.endswith(IAC_SUFFIXES):
            stacks["iac"] = True

    if ".swift" in suffixes:
        stacks["swift"] = True
    if suffixes & {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        stacks["javascript"] = True
    if ".py" in suffixes:
        stacks["python"] = True
    if ".go" in suffixes:
        stacks["go"] = True

    stacks["code"] = any(stacks[k] for k in ("swift", "javascript", "python", "go"))
    return stacks
