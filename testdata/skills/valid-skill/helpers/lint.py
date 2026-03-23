"""Helper script for running linters."""

import json
import sys


def run_lint(path: str) -> dict:
    """Run basic lint checks on a file."""
    with open(path) as f:
        content = f.read()

    issues = []
    for i, line in enumerate(content.splitlines(), 1):
        if len(line) > 120:
            issues.append({"line": i, "message": "Line too long"})

    return {"path": path, "issues": issues}


if __name__ == "__main__":
    result = run_lint(sys.argv[1])
    print(json.dumps(result, indent=2))
