# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.5.0]
### Added
- Source-aware deep SQL injection analysis. The deep checks now follow
  common request-input patterns instead of treating constant-only SQL
  concatenation as an injection risk: Flask/Django-style `request.*`,
  Express-style `req.*`, Java servlet `request.getParameter`, Go form
  values, ASP.NET `Request.*`, PHP superglobals, and Rails `params`.
- Same-file helper return tracking for query builders, including helpers
  that assign the unsafe query to a local variable before returning it.
- Simple instance-field tracking (`self.query`, `this.query`, `$this->query`,
  and Ruby instance variables) and conservative branch merging.

### Fixed
- SQL sinks now inspect the query argument only, rather than mistakenly
  treating separately-bound parameter values as executable SQL.
- Added regression coverage for trusted constant concatenation, direct
  source-to-sink flow, returned queries, instance fields, and branches.

## [0.4.0]
### Fixed
- Dedup, remove unsound placeholder filter, port Python to parity.

- scanner.py: dedup by (vuln family, file, line) instead of (file, line).
- remove SAFE_PLACEHOLDER regex from all deep SQLi checks and the
  line-based check; a placeholder token existing in a line never
  proved the rest of the line was safe.
- port Python's deep check onto taint_common.py (shared engine),
  giving it cross-function tracking and .format() detection like
  the other 7 languages.
- add is_unqualified_call to prevent cross-function tracking from
  matching a receiver-qualified call (obj.query()) against a
  same-named local function.
- add simple identifier alias tracking (a = b, where b is tainted).
- add tools/fetch_node_types.py and tools/verify_node_types.py to
  check language-config assumptions against each grammar's real
  node-types.json, and tools/run_functional_checks.py as a
  real-parser regression suite (33 cases, all 8 languages).

## [0.3.1]
### Fixed
- Added working changelog, repository, and PyPI release-history links
  to the package metadata and project README.

## [0.3.0]
### Added
- Cross-function taint tracking (single file, one level deep): if a
  tainted variable is passed into another function defined in the
  same file, and that function executes it, it's now caught. Does
  NOT catch a helper function that builds and returns a tainted
  query for the caller to execute - that direction is not tracked.
- Format-string detection for Java (`String.format`) and Go
  (`fmt.Sprintf`) as a second unsafe-construction pattern, alongside
  concatenation, since neither language has native interpolation.
- Deduplication: when the line-based check and a deep check both
  flag the same file and line, only the deep finding is kept.

### Fixed
- `%s` was incorrectly treated as a "safe" SQL placeholder in Java
  and Go, even though it's actually the format specifier for
  `String.format`/`Sprintf` in those languages - this could hide a
  real inline SQL injection finding. Fixed for Java and Go
  specifically; other languages still treat `%s` as safe where it's
  a legitimate database placeholder (e.g. Python's psycopg2).

## [0.2.0]
### Added
- Deep (syntax-tree based) SQL injection detection extended from
  Python-only to all 8 supported languages: JavaScript, TypeScript,
  PHP, Java, C#, Ruby, Go. Built on one shared taint-tracking engine
  (`taint_common.py`) with a small per-language config, instead of
  duplicating the algorithm per language.
- C#'s deep check treats `new SqlCommand(query)` itself as a sink,
  not just `.ExecuteReader()`, since the real danger point is often
  the constructor call, several lines before execution happens.

## [0.1.1]
### Fixed
- Added `readme = "README.md"` to package metadata so PyPI displays
  the actual project description instead of "no description
  provided."

## [0.1.0]
### Added
- Initial release: line-based SQL injection detection across 8
  languages (Python, JS, TS, PHP, Java, C#, Ruby, Go), plus a deep,
  syntax-tree-based SQL injection check for Python specifically,
  using tree-sitter to track a variable across multiple lines.
