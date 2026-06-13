# 🐱 mcp-cateye

**MCP Server Security Scanner** — fuzzing + static analysis. Cat's eye sees what others miss.

[![PyPI](https://img.shields.io/pypi/v/mcp-cateye)](https://pypi.org/project/mcp-cateye/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-cateye)](https://pypi.org/project/mcp-cateye/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

### Dynamic Analysis (Fuzzing)
- **Active fuzzing** of MCP server tools with 50+ payloads across 9 categories
- Command injection, path traversal, SSRF, prompt injection, SQL injection, XSS, SSTI, info disclosure, deserialization
- Category filtering for targeted testing
- JSON output for CI/CD integration

### Static Analysis (NEW in v1.1.0)
- **Config Discovery** — scan Claude, Cursor, VS Code, Windsurf, Zed, Cline, RooCode configs
- **Secrets Detection** — find hardcoded API keys, tokens, passwords (OpenAI, GitHub, AWS, Slack, JWT, etc.)
- **Tool Description Analysis** — detect poisoning, rug pull, prompt injection, over-privileged tools
- **Dependency Scanning** — pip-audit integration for known CVEs
- **Readiness Checks** — AST-based analysis for missing timeouts, shell=True, bare excepts
- **Security Score** — 0-100 score with A-F grade breakdown
- **AI-BOM** — CycloneDX 1.5 JSON bill of materials for MCP servers

## Installation

```bash
pip install mcp-cateye
```

## Quick Start

### Fuzz an MCP server
```bash
# Fuzz all tools
mcp-cateye fuzz python -- -m my_mcp_server

# Fuzz specific categories
mcp-cateye fuzz -c cmd -c ssrf node -- server.js

# JSON output for CI
mcp-cateye fuzz --json python -- server.py
```

### Static analysis
```bash
# Full scan
mcp-cateye scan .

# Quick security score
mcp-cateye score .

# Generate AI-BOM
mcp-cateye scan . --aibom

# Scan specific clients
mcp-cateye scan . --clients claude --clients cursor
```

### List tools and payloads
```bash
# List tools on a server
mcp-cateye list-tools python -- -m my_mcp_server

# List available payloads
mcp-cateye list-payloads
```

## Security Score

The `score` command gives a quick 0-100 rating:

```
🐱 mcp-cateye — Security Score

  🟡 B+  [██████████████████████░░░░░░░░]  72/100

  Breakdown:
    fuzzing              [████████████████████] 100/100
    secrets              [██████████░░░░░░░░░░]  50/100
    dependencies         [████████████████████] 100/100
    tool_descriptions    [██████████████░░░░░░]  70/100
    readiness            [████████████████░░░░]  80/100
```

## Payload Categories

| Category | Count | Examples |
|----------|-------|---------|
| Command Injection | 8 | `$(whoami)`, backticks, `os.system` |
| Path Traversal | 6 | `../../etc/passwd`, null bytes |
| SSRF | 6 | `http://169.254.169.254`, DNS rebinding |
| Prompt Injection | 7 | Ignore instructions, role hijack |
| SQL Injection | 6 | Union, blind, time-based |
| XSS | 5 | Script tags, event handlers |
| Template Injection | 5 | Jinja2, Twig, Freemarker |
| Info Disclosure | 4 | Stack traces, debug endpoints |
| Deserialization | 4 | Pickle, YAML unsafe |

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install mcp-cateye
    mcp-cateye scan . --json > report.json
    mcp-cateye score .
```

Exit codes:
- `0` — No critical findings
- `1` — Critical findings detected

## Why mcp-cateye?

Most MCP security tools only do static analysis. mcp-cateye is the only tool that combines:

1. **Active fuzzing** — actually sends malicious payloads to MCP servers
2. **Static analysis** — scans configs, code, and dependencies
3. **Security scoring** — gives you a single number to track

Cat's eye sees what others miss. 🐱

## License

MIT
