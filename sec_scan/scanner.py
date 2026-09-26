import argparse
import os
import sys

from .checks.registry import load_checks

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
             "dist", "build", "bin", "obj", ".idea", ".vscode"}


def collect_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def main():
    parser = argparse.ArgumentParser(description="Scan a codebase for security issues.")
    parser.add_argument("path", nargs="?", default=".",
                         help="File or folder to scan (default: current directory)")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: path '{args.path}' does not exist.")
        sys.exit(1)

    checks = load_checks()
    if not checks:
        print("No checks registered yet.")
        sys.exit(0)

    files = [args.path] if os.path.isfile(args.path) else list(collect_files(args.path))

    all_findings = []
    for file_path in files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (IsADirectoryError, PermissionError):
            continue

        ext = os.path.splitext(file_path)[1]

        for check in checks:
            if ext in check.EXTENSIONS:
                findings = check.run(file_path, content)
                all_findings.extend(findings)

    print_report(all_findings, len(files), len(checks))


def print_report(findings, file_count, check_count):
    print(f"\nScanned {file_count} file(s) with {check_count} check(s).\n")

    if not findings:
        print("No issues found.")
        return

    findings.sort(key=lambda f: f["line"])

    for f in findings:
        print(f"[{f['severity']}] {f['check_id']}")
        print(f"  {f['file']}:{f['line']}")
        print(f"  {f['message']}")
        print(f"  >> {f['snippet'].strip()}")
        print()

    print(f"Total findings: {len(findings)}")


if __name__ == "__main__":
    main()