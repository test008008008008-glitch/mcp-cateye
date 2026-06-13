# 🐱 mcp-cateye

> Cat's eye sees what others miss.

**MCP Server security scanner with fuzzing** — the first tool that actually
*attacks* MCP servers to find vulnerabilities, not just reads their config files.

[![PyPI version](https://img.shields.io/pypi/v/mcp-cateye.svg)](https://pypi.org/project/mcp-cateye/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why mcp-cateye?

Every other MCP security tool does **static analysis** — they read your config,
list your tools, check permission declarations. That's like checking if a door
*looks* locked without trying the handle.

**mcp-cateye actually tries the handle.** It connects to your MCP server,
enumerates every tool, and fires real attack payloads at every parameter:

| Category | Payloads | What it tests |
|----------|----------|---------------|
| 🔴 Command Injection | 9 | `$(id)`, `` `whoami` ``, `; cat /etc/passwd` |
| 🟠 Path Traversal | 5 | `../../../etc/passwd`, URL-encoded bypasses |
| 🔴 Prompt Injection | 5 | System prompt extraction, DAN jailbreak |
| 🔴 SSRF | 7 | AWS/GCP/Alibaba metadata, Redis, file:// |
| 🟠 Template Injection | 5 | `{{7*7}}`, `${7*7}`, Jinja2 globals |
| 🟠 SQL Injection | 4 | UNION, tautology, time-based blind |
| 🟡 XSS | 3 | `<script>`, `<img onerror>`, attribute breakout |
| 🔴 Info Disclosure | 3 | `.env`, `.git/config`, `config.yaml` |
| 🔴 Deserialization | 2 | Python pickle, PHP unserialize |

Then it **checks the response** — if the server returns `uid=0`, command
execution confirmed. If it returns `/etc/passwd` content, file read confirmed.
If it echoes the system prompt, prompt leak confirmed.

## Installation

```bash
pip install mcp-cateye
```

Or with uv:
```bash
uv tool install mcp-cateye
```

## Quick Start

```bash
# List tools on a server
mcp-cateye list-tools python -m my_mcp_server

# Fuzz everything
mcp-cateye fuzz python -m my_mcp_server

# Fuzz specific categories
mcp-cateye fuzz uvx mcp-server-git -c cmd -c ssrf

# JSON output for CI/CD
mcp-cateye fuzz node server.js --json

# With environment variables
mcp-cateye fuzz python server.py -e API_KEY=sk-xxx -e DEBUG=true
```

## Example Output

```
╔══════════════════════════════════════════════════════════╗
║              🐱 mcp-cateye Scan Report                  ║
╚══════════════════════════════════════════════════════════╝

  Server:  python -m my_mcp_server
  Tools:   3
  Tests:   540
  Time:    12.3s

  ── Findings ────────────────────────────────────────────
  🔴 Critical: 2
  🟠 High:     1
  🟡 Medium:   0
  🔵 Low:      1
  📊 Total:    4

  1. 🔴 [CRITICAL] run_command.command — Subshell command execution via $()
     Payload: $(id)
     Response: uid=501(cat) gid=20(staff) groups=20(staff)...

  2. 🔴 [CRITICAL] read_file.path — Unix path traversal to /etc/passwd
     Payload: ../../../etc/passwd
     Response: root:*:0:0:System Administrator:/var/root:/bin/sh...

  🐱 Scan complete. Cat's eye sees all.
```

## How It Works

1. **Connect** — launches the MCP server via stdio and initializes a session
2. **Enumerate** — calls `list_tools()` to discover every tool and its parameters
3. **Fuzz** — for each tool × parameter × payload, sends the payload and
   inspects the response
4. **Detect** — checks responses against detection patterns (e.g., `uid=` in
   output = command injection confirmed)
5. **Report** — outputs findings with severity, confidence, and response snippets

## Use Cases

- **MCP Server Developers**: Test your server before publishing
- **Security Researchers**: Find 0-days in popular MCP servers
- **CI/CD Pipelines**: `mcp-cateye fuzz ... --json` in your test suite
- **MCP Registry Maintainers**: Audit servers before listing

## vs. Other Tools

| Feature | mcp-cateye | mcp-scan | cisco-mcp-scanner | snyk-agent-scan | antgroup/MCPScan |
|---------|------------|----------|-------------------|-----------------|------------------|
| Static analysis | ❌ | ✅ | ✅ | ✅ | ✅ |
| Active fuzzing | ✅ | ❌ | ❌ | ❌ | ❌ |
| Command injection | ✅ | ❌ | ❌ | ❌ | ❌ |
| SSRF detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| Prompt injection | ✅ | ✅ | ❌ | ✅ | ❌ |
| Template injection | ✅ | ❌ | ❌ | ❌ | ❌ |
| Response-based detection | ✅ | ❌ | ❌ | ❌ | ❌ |

## License

MIT © 2026 cat

---

🐱 *The cat's eye sees in the dark. Your MCP server's vulnerabilities can't hide.*
