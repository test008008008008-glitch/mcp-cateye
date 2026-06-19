# Changelog

All notable changes to **mcp-cateye** are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] — 2026-06-20

### Fixed
- **AI-BOM tool version was hardcoded to `1.1.0`** and never reflected the
  package version. Now reads from `mcp_cateye.__version__`, so the
  CycloneDX `metadata.tools[].version` field always matches the running
  release.
- **AI-BOM filename stripped all dots** (`aibom-./mcp.json`), producing
  empty or malformed filenames for paths like `..` or `...`. Replaced
  with a safe `-`-joined component list; bare `.` and `..` fall back to
  `aibom-current.json`.
- **False positive: `template_injection` payload `{{self.__init__.__globals__}}`**
  was reported on every response containing the substring `os`
  (e.g. `enclosed property`). The detection helper now uses
  word-boundary matching for short patterns (`< 4` chars), so `os` matches
  `import os` / `os.system` but no longer matches `enclosed`,
  `composed`, etc.
- **False negative on Python/shell error responses** like
  `Expecting property name enclosed in double quotes` and
  `/bin/sh: uid=501(cat): command not found`. The error-response
  heuristic now has a list of *strong* indicators (`/bin/sh:`,
  `expecting`, `unterminated`, `Traceback (most recent call last)`, ...)
  that flag the response as an error on a single match, instead of
  requiring two weak indicators in the prefix.

### Tests
- Added `test_detect_in_response_word_boundary` covering the short-pattern
  fix (`os` / `49` boundary cases).
- Added `test_is_error_response` covering strong indicators, weak
  indicators, and negative cases.

## [1.2.0] — 2026-06-18

### Added
- Context-aware payload generation: the scanner now consults the target
  tool's `inputSchema` to produce argument values that match the
  declared type (string, integer, boolean, array, object).
- HTML report output (`-o html -s report.html`).
- Grade letter (A+ to F) shown next to the numeric security score.

### Changed
- Detection patterns are matched case-insensitively across the whole
  response, not just the prefix.
- Error-based detection only marks a finding as high confidence when
  the payload category is one of `command_injection`, `path_traversal`,
  or `ssrf` (categories where an error response itself proves the vuln).

## [1.1.0] — 2026-06-12

### Added
- `score` command: quick 0-100 security score with letter grade.
- `--json` shorthand for `-o json`.
- AIBOM (CycloneDX 1.5) export via `mcp-cateye scan . --aibom`.

### Changed
- Static analyzer groups findings by category and surfaces the worst
  severity in the summary line.

## [1.0.1] — 2026-06-04

### Fixed
- `mcp-cateye` console script entry point now resolves correctly when
  the package is installed in editable mode.
- `discover_configs` no longer raises when `~/.cursor/` is missing.

### Added
- First published release on PyPI.
- `fuzz`, `scan`, `score`, `list-payloads`, `list-tools` subcommands.
