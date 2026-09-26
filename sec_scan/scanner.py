#!/usr/bin/env python3
"""
scanner.py - entry point for the security scanner CLI.
"""

import argparse
import os
import sys

import colorama
from colorama import Fore, Style

from .checks.registry import load_checks

colorama.init(autoreset=True)

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
             "dist", "build", "bin", "obj", ".idea", ".vscode"}

SEVERITY_COLORS = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
}


def collect_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def dedup_findings(findings):
    """If a deep check (check_id ending in '-DEEP') found something at
    the exact same file+line as a non-deep check, drop the non-deep
    one - it's the same bug, and the deep finding is strictly more
    informative, so keeping both is just noise, not two different
    bugs."""
    deep_locations = {
        (f["file"], f["line"])
        for f in findings
        if f["check_id"].endswith("-DEEP")
    }
    result = []
    for f in findings:
        if not f["check_id"].endswith("-DEEP") and (f["file"], f["line"]) in deep_locations:
            continue
        result.append(f)
    return result


def main():
    parser = argparse.ArgumentParser(description="Scan a codebase for security issues.")
    parser.add_argument("path", nargs="?", default=".",
                         help="File or folder to scan (default: current directory)")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"{Fore.RED}Error: path '{args.path}' does not exist.{Style.RESET_ALL}")
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

    all_findings = dedup_findings(all_findings)
    print_report(all_findings, len(files), len(checks))


def print_report(findings, file_count, check_count):
    print(f"\nScanned {file_count} file(s) with {check_count} check(s).\n")

    if not findings:
        print(f"{Fore.GREEN}No issues found.{Style.RESET_ALL}")
        return

    findings.sort(key=lambda f: f["line"])

    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "")
        print(f"{color}[{f['severity']}] {f['check_id']}{Style.RESET_ALL}")
        print(f"  {f['file']}:{f['line']}")
        print(f"  {f['message']}")
        print(f"  >> {f['snippet'].strip()}")
        print()

    print(f"{Fore.RED}Total findings: {len(findings)}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()