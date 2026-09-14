"""Extract source-code snippets around findings so the UI can show the
flagged code inline (Aikido-style), without bloating raw scan output."""
from pathlib import Path

from gatekeeper.core.detect import SKIP_DIRS

MAX_SNIPPET_BYTES = 400_000
TEXT_EXTS = {
    ".swift", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go",
    ".rb", ".java", ".kt", ".kts", ".php", ".c", ".h", ".cpp", ".hpp",
    ".cs", ".rs", ".yml", ".yaml", ".json", ".toml", ".xml", ".html",
    ".css", ".scss", ".sql", ".sh", ".bash", ".zsh", ".env", ".txt",
    ".md", ".tf", ".tfvars", ".properties", ".gradle", ".plist",
}
TEXT_NAMES = {"Dockerfile", "Makefile", ".env", ".gitignore", "Podfile"}


def _is_readable(path: Path) -> bool:
    if path.name in TEXT_NAMES or path.suffix.lower() in TEXT_EXTS:
        return True
    return path.suffix == "" and path.is_file()


def code_snippet(target, file: str, line: int, context: int = 5) -> str:
    """Numbered source excerpt around `line`. Empty string when unavailable."""
    if not file or not line:
        return ""
    root = Path(target)
    path = root / file if not Path(file).is_absolute() else Path(file)
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return ""
    if any(part in SKIP_DIRS for part in path.parts):
        return ""
    if not path.is_file() or not _is_readable(path):
        return ""
    try:
        if path.stat().st_size > MAX_SNIPPET_BYTES:
            return ""
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if not (1 <= line <= len(lines) + context):
        return ""
    start = max(0, line - context - 1)
    end = min(len(lines), line + context)
    return "\n".join(f"{i + 1:4d}| {lines[i]}" for i in range(start, end))
