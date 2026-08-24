from pathlib import Path


PATTERNS = {
    "sqli": [
        "execute(query)",
        "WHERE id=",
        "WHERE id='",
    ],

    "xss": [
        "document.body.dataset",
        "render_template_string",
        "const labValue",
    ],

    "file": [
        "open(",
        "os.path.join",
        "urllib.request.urlopen",
    ],

    "auth": [
        "FAILED.setdefault",
        "Retry-After",
        "mfa_pending",
    ],
}


IGNORED_DIRECTORIES = {
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".git",
    "node_modules",
}


def is_ignored(file: Path, root: Path) -> bool:
    try:
        relative = file.relative_to(root)
    except ValueError:
        return True

    return any(
        part in IGNORED_DIRECTORIES
        for part in relative.parts
    )


def analyze(source_path: str):

    root = Path(source_path).resolve()

    if not root.exists():
        return []

    if not root.is_dir():
        return []

    hits = []

    for file in root.rglob("*.py"):

        if is_ignored(file, root):
            continue

        try:
            text = file.read_text(
                encoding="utf-8",
                errors="ignore",
            )

        except Exception:
            continue

        for category, patterns in PATTERNS.items():

            for pattern in patterns:

                if pattern not in text:
                    continue

                hits.append({
                    "category": category,
                    "file": str(file),
                    "pattern": pattern,
                })

    return hits
