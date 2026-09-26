# sec-scan

A command-line security scanner, built from scratch and growing one vulnerability check at a time. It walks a codebase and flags patterns that look like known vulnerability classes. No external scanning services, no network calls, no data leaves your machine.

## What it checks for right now

- **SQL Injection (line-based)**: flags lines where a SQL-executing call (`execute`, `query`, `ExecuteReader`, etc.) is combined with string concatenation or interpolation (`+`, f-strings, `.format()`, template literals, C#'s `$"..."`) instead of a safe parameterized placeholder (`?`, `%s`, `@name`, `:name`). Applies to: `.py .js .ts .php .java .cs .rb .go`

- **SQL Injection (deep)**: parses source code into a real syntax tree instead of reading text line by line, tracks which variables were built from unsafe string concatenation or interpolation, and follows that variable across lines within the same function until it either reaches a SQL sink or gets safely reassigned. This catches a common gap in the line-based check: a query assembled on one line and executed several lines later. Applies to: `.py .js .ts .php .java .cs .rb .go` (all 8 languages now have a deep checker, each with its own small set of language-specific limitations, documented in that check's own source file, e.g. Java and Go have no native string interpolation so only concatenation is tracked; Go's `fmt.Sprintf` pattern is a known gap; taint tracking does not follow a value once it's passed into another function).

Since both checks currently run on every file, you will often see two findings for the same underlying bug: one from the line-based check and one from the deep check. That's expected for now; deduplication is a known future improvement, not a bug.

More checks will be added over time, each getting its own section here, the same way the entries above do.

## Install

    pip install sec-scan

If pip refuses with an "externally managed environment" error:

    pip install sec-scan --break-system-packages

(Or use a virtualenv if you'd rather keep it isolated, either works.)

This installs several dependencies alongside sec-scan itself:`tree-sitter` plus one grammar package per supported language (`tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-typescript`, `tree-sitter-php`, `tree-sitter-java`, `tree-sitter-c-sharp`, `tree-sitter-ruby`, `tree-sitter-go`), and `colorama` for colored terminal output on Windows and Linux/macOS.

### Installing for development

If you're working on sec-scan itself rather than just using it, clone the repo and install in editable mode instead, so changes to the source take effect immediately without reinstalling:

    git clone https://github.com/George-20m/sec-scan.git
    cd sec-scan
    pip install -e .

## Use

From inside any project you want to check:

    sec-scan .

That scans the current directory. To scan a specific folder or file instead:

    sec-scan path/to/folder
    sec-scan path/to/file.py

Findings are color-coded by severity in the terminal (red for HIGH, yellow for MEDIUM, cyan for LOW) so the report is easier to scan at a glance. A clean scan prints in green.

## How it works

This isn't a full production-grade static analyzer, it's intentionally lightweight detection, built in stages:

- The line-based check reads each line as text and looks for a dangerous pattern sitting next to a SQL call. Fast, works on any of the eight supported languages, but only sees one line at a time, so a query built across multiple lines can slip past it.
- The deep check instead parses the file into a proper syntax tree and follows a variable's origin within a function, so it can catch the multi-line case above. All 8 languages now have their own deep checker, sharing one taint-tracking engine (`taint_common.py`) so the core algorithm is written once, and each language only supplies its own grammar-specific details.

Findings should be reviewed by a human, not treated as a guarantee of safety or the absence of bugs. That's true of every static analysis tool, not just this one. Known limitations for each check are documented in that check's own source file.

## Project structure

    sec-scan/
    ├── pyproject.toml
    └── sec_scan/
        ├── scanner.py                     # CLI entry point, walks files, runs checks
        └── checks/
            ├── registry.py                  # auto-discovers check modules
            ├── sql_injection.py             # line-based SQL injection check
            ├── taint_common.py              # shared taint-tracking engine
            ├── sql_injection_deep.py        # deep check: Python
            ├── sql_injection_deep_js.py     # deep check: JavaScript, TypeScript
            ├── sql_injection_deep_php.py    # deep check: PHP
            ├── sql_injection_deep_java.py   # deep check: Java
            ├── sql_injection_deep_csharp.py # deep check: C#
            ├── sql_injection_deep_ruby.py   # deep check: Ruby
            └── sql_injection_deep_go.py     # deep check: Go

Adding a new check means adding one new file to `sec_scan/checks/` that defines `EXTENSIONS` (a set of file extensions) and `run(file_path, content)` (returns a list of finding dicts). It's picked up automatically, nothing else needs to change.