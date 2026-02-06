from __future__ import annotations

import sys
from pathlib import Path

MAX_LINE_LENGTH = 100


def iter_python_files(root: Path):
    for path in root.rglob("*.py"):
        if ".venv" in path.parts:
            continue
        yield path


def lint_file(path: Path) -> list[str]:
    errors = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if "\t" in line:
            errors.append(f"{path}:{idx}: tabs are not allowed")
        if len(line) > MAX_LINE_LENGTH:
            errors.append(
                f"{path}:{idx}: line too long ({len(line)} > {MAX_LINE_LENGTH})"
            )
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    for path in iter_python_files(root / "src"):
        errors.extend(lint_file(path))
    for path in iter_python_files(root / "tests"):
        errors.extend(lint_file(path))
    if errors:
        print("\n".join(errors))
        return 1
    print("lint ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
