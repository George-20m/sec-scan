# sec-scan

A command-line security scanner, built from scratch and growing one
vulnerability check at a time. It walks a codebase and flags patterns
that look like known vulnerability classes — no external scanning
engines, no API calls, pure Python standard library.

## What it checks for right now

- **SQL Injection** — flags lines where a SQL-executing call
  (`execute`, `query`, `ExecuteReader`, etc.) is combined with string
  concatenation or interpolation (`+`, f-strings, `.format()`,
  template literals, C#'s `$"..."`) instead of a safe parameterized
  placeholder (`?`, `%s`, `@name`, `:name`).
  Applies to: `.py .js .ts .php .java .cs .rb .go`

More checks will be added over time — each one gets its own section
here explaining what it looks for and why, the same way the entry
above does.

## Install

From inside this repo's root folder (where `pyproject.toml` lives):

    pip install -e .

If pip refuses with an "externally managed environment" error:

    pip install -e . --break-system-packages

(Or use a virtualenv if you'd rather keep it isolated — either works.)

## Use

From inside any project you want to check:

    sec-scan .

That scans the current directory. To scan a specific folder or file
instead:

    sec-scan path/to/folder
    sec-scan path/to/file.py

## How it works

This isn't a full static analyzer with a real language parser — it's
intentionally lightweight pattern matching. For each file, it checks
the extension against what each check module declares it applies to,
then runs that check line by line looking for a dangerous pattern.

That trade-off means it's fast and dependency-free, but it has real
limitations — for example, the SQL injection check only looks at one
line at a time, so a query built across multiple lines can be missed.
Known limitations are documented in each check's own file.

## Project structure

    sec-scan/
    ├── pyproject.toml
    └── sec_scan/
        ├── scanner.py       # CLI entry point, walks files, runs checks
        └── checks/
            ├── registry.py       # auto-discovers check modules
            └── sql_injection.py  # SQL injection check

Adding a new check means adding one new file to `sec_scan/checks/`
that defines `EXTENSIONS` (a set of file extensions) and
`run(file_path, content)` (returns a list of finding dicts). It's
picked up automatically — nothing else needs to change.