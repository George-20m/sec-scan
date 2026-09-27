# sec-scan

A command-line security scanner, built from scratch and growing one
vulnerability check at a time. It walks a codebase and flags patterns
that look like known vulnerability classes. No external scanning
services, no network calls, no data leaves your machine.

See [CHANGELOG.md](CHANGELOG.md) for what changed between versions.

## What it checks for right now

- **SQL Injection (line-based)**: flags lines where a SQL-executing
  call (`execute`, `query`, `ExecuteReader`, etc.) is combined with
  string concatenation or interpolation (`+`, f-strings, `.format()`,
  template literals, C#'s `$"..."`) instead of a safe parameterized
  placeholder (`?`, `%s`, `@name`, `:name`).
  Applies to: `.py .js .ts .php .java .cs .rb .go`

- **SQL Injection (deep)**: parses source code into a real syntax
  tree instead of reading text line by line, tracks which variables
  were built from unsafe string concatenation, interpolation, or
  (for Java and Go) unsafe use of `String.format`/`fmt.Sprintf`, and
  follows that variable across lines within the same function until
  it either reaches a SQL sink or gets safely reassigned. It also
  follows a tainted value one level deep into another function
  defined in the same file, if that function itself executes it.
  Applies to: `.py .js .ts .php .java .cs .rb .go` (all 8 languages).

  Known limitations, documented per-check in each check's own
  source file: taint tracking does not follow a value across files,
  through recursive/cyclic calls, or through a helper function that
  builds and *returns* a query for the caller to execute (only
  "passed in and executed directly" is tracked, not "returned and
  executed later").

When both the line-based and deep check would flag the same file and
line, only the deep finding is shown, since it's the same underlying
bug and the deep finding is more informative. You may still see
separate findings from each check on different lines of the same
file, which reflect genuinely different issues.

More checks will be added over time, each getting its own section
here, the same way the entries above do.

## Install

    pip install sec-scan

If pip refuses with an "externally managed environment" error:

    pip install sec-scan --break-system-packages

(Or use a virtualenv if you'd rather keep it isolated, either works.)

This installs several dependencies alongside sec-scan itself:
`tree-sitter` plus one grammar package per supported language
(`tree-sitter-python`, `tree-sitter-javascript`,
`tree-sitter-typescript`, `tree-sitter-php`, `tree-sitter-java`,
`tree-sitter-c-sharp`, `tree-sitter-ruby`, `tree-sitter-go`), and
`colorama` for colored terminal output on Windows and Linux/macOS.

### Installing for development

If you're working on sec-scan itself rather than just using it, clone
the repo and install in editable mode instead, so changes to the
source take effect immediately without reinstalling:

    git clone https://github.com/George-20m/sec-scan.git
    cd sec-scan
    pip install -e .

## Use

From inside any project you want to check:

    sec-scan .

That scans the current directory. To scan a specific folder or file
instead:

    sec-scan path/to/folder
    sec-scan path/to/file.py

Findings are color-coded by severity in the terminal (red for HIGH,
yellow for MEDIUM, cyan for LOW) so the report is easier to scan at
a glance. A clean scan prints in green.

## How it works

This isn't a full production-grade static analyzer, it's
intentionally lightweight detection, built in stages:

- The line-based check reads each line as text and looks for a
  dangerous pattern sitting next to a SQL call. Fast, works on any
  of the eight supported languages, but only sees one line at a
  time, so a query built across multiple lines can slip past it.
- The deep check instead parses the file into a proper syntax tree
  and follows a variable's origin within a function (and one level
  into another function in the same file, if it's passed there and
  executed). All 8 languages share one taint-tracking engine
  (`taint_common.py`), so the core algorithm is written once, and
  each language only supplies its own grammar-specific details.

Findings should be reviewed by a human, not treated as a guarantee
of safety or the absence of bugs. That's true of every static
analysis tool, not just this one. Known limitations for each check
are documented in that check's own source file.

## Project structure

    sec-scan/
    ├── pyproject.toml
    ├── CHANGELOG.md
    └── sec_scan/
        ├── scanner.py                     # CLI entry point, walks files, runs checks, dedups findings
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

Adding a new check means adding one new file to `sec_scan/checks/`
that defines `EXTENSIONS` (a set of file extensions) and
`run(file_path, content)` (returns a list of finding dicts). It's
picked up automatically, nothing else needs to change.