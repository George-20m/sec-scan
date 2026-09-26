# sec-scan

A command-line security scanner, built from scratch and growing one
vulnerability check at a time. It walks a codebase and flags patterns
that look like known vulnerability classes. No external scanning
services, no network calls, no data leaves your machine.

## What it checks for right now

- **SQL Injection (line-based)** — flags lines where a SQL-executing
  call (`execute`, `query`, `ExecuteReader`, etc.) is combined with
  string concatenation or interpolation (`+`, f-strings, `.format()`,
  template literals, C#'s `$"..."`) instead of a safe parameterized
  placeholder (`?`, `%s`, `@name`, `:name`).
  Applies to: `.py .js .ts .php .java .cs .rb .go`

- **SQL Injection (deep, Python only)** — parses Python into a real
  syntax tree instead of reading text line by line, and tracks
  variables built from unsafe string concatenation across multiple
  lines within a function. This catches a common gap in the
  line-based check: a query assembled on one line and executed
  several lines later.

For Python files, both checks run and you may see two findings for
the same underlying bug — one from each check. That's expected for
now; deduplication is a known future improvement.

More checks, and deep analysis for more languages, will be added
over time — each one gets its own section here, the same way the
entries above do.

## Install

    pip install -e .

If pip refuses with an "externally managed environment" error:

    pip install -e . --break-system-packages

(Or use a virtualenv if you'd rather keep it isolated — either works.)

This installs two dependencies alongside sec-scan itself:
`tree-sitter` and `tree-sitter-python`, which power the deep Python
check above.

## Use

From inside any project you want to check:

    sec-scan .

That scans the current directory. To scan a specific folder or file
instead:

    sec-scan path/to/folder
    sec-scan path/to/file.py

## How it works

This isn't a full production-grade static analyzer — it's
intentionally lightweight detection, built in stages:

- The line-based check reads each line as text and looks for a
  dangerous pattern sitting next to a SQL call. Fast, works on any
  of the eight supported languages, but only sees one line at a
  time — a query built across multiple lines can slip past it.
- The deep Python check instead parses the file into a proper syntax
  tree and follows a variable's origin within a function, so it can
  catch the multi-line case above. It's Python-only for now, and it
  doesn't follow a value once it's passed into another function.

Findings should be reviewed by a human, not treated as a guarantee
of safety or the absence of bugs — that's true of every static
analysis tool, not just this one. Known limitations for each check
are documented in that check's own source file.

## Project structure

    sec-scan/
    ├── pyproject.toml
    └── sec_scan/
        ├── scanner.py               # CLI entry point, walks files, runs checks
        └── checks/
            ├── registry.py          # auto-discovers check modules
            ├── sql_injection.py       # line-based SQL injection check
            └── sql_injection_deep.py  # tree-sitter based SQL injection check (Python)

Adding a new check means adding one new file to `sec_scan/checks/`
that defines `EXTENSIONS` (a set of file extensions) and
`run(file_path, content)` (returns a list of finding dicts). It's
picked up automatically — nothing else needs to change.
