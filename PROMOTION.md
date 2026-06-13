# MCP-CATEYE PROMOTION CONTENT

Draft posts for Hacker News, Reddit, Twitter, and dev.to.
User posts manually after review (HN/Reddit need login, Twitter needs API).

## 1. Hacker News — "Show HN" Post

**Title** (max 80 chars):
Show HN: mcp-cateye – MCP security tool that actually fuzzes (not just static analysis)

**URL**: https://github.com/test008008008008-glitch/mcp-cateye

**Text** (HN allows extra context for Show HN):
```
Hey HN,

I built mcp-cateye because every existing MCP security tool I looked at
did ONE thing well: static analysis, OR config scanning, OR poisoning
detection. None of them actually sent attack payloads to a running MCP
server.

mcp-cateye is the first open-source tool that does all four in one CLI:

• Active fuzzing – 50+ attack payloads across 9 categories (cmd injection,
  path traversal, SSRF, prompt injection, SQLi, XSS, SSTI, info disclosure,
  deserialization). The fuzzer spawns the MCP server via stdio, lists its
  tools, then mutates parameters and inspects responses.
• Static analysis – config discovery (Claude/Cursor/VS Code/Windsurf/Zed/
  Cline), secrets detection (OpenAI/GitHub/AWS/JWT patterns), tool
  description poisoning detection, pip-audit for dep CVEs, AST-based
  readiness checks.
• Security scoring – 0-100 + A-F grade with category breakdown.
• AI-BOM – CycloneDX 1.5 JSON bill of materials.

It's MIT-licensed, ~800 LOC of core engine, 40 tests passing.

Install: pip install git+https://github.com/test008008008008-glitch/mcp-cateye.git

Demo against a deliberately vulnerable server:
  mcp-cateye fuzz python -- -m mcp_cateye.vuln_server
  → catches cmd injection, path traversal, SSRF in <10s

Would love feedback on what attack categories to add next, and whether
anyone wants a YARA-rule based scanner layered on top.
```

---

## 2. Reddit r/netsec Post

**Title**:
[mcp-cateye] Open-source MCP security scanner that actually fuzzes (catches cmd injection that static scanners miss)

**Body**:
```markdown
Hey r/netsec,

Sharing a tool I built because the MCP security space had a gap I kept
running into: https://github.com/test008008008008-glitch/mcp-cateye

## The gap I found

I started auditing MCP servers as a security researcher and kept finding
command-injection-style bugs that every existing tool missed. The MCP
security scanners I tried (the Cisco one, the APIsec one, the
Invariant Labs one) each did one thing well: static analysis, config
scanning, or poisoning detection. None of them actually **spawned the
MCP server and probed it with attack payloads**.

## What mcp-cateye does

It runs all four kinds of analysis in one CLI:

1. **Active fuzzing** – spawns the MCP server via stdio, enumerates
   tools, mutates each parameter with 50+ attack payloads across 9
   categories (cmd injection, path traversal, SSRF, prompt injection,
   SQLi, XSS, SSTI, info disclosure, deserialization).
2. **Static analysis** – config discovery (Claude Desktop, Cursor,
   VS Code, Windsurf, Zed, Cline), secrets detection (OpenAI / GitHub
   / AWS / JWT patterns), tool description poisoning detection,
   pip-audit for dep CVEs, AST-based readiness checks.
3. **Security scoring** – 0-100 + A-F grade with category breakdown.
4. **AI-BOM** – CycloneDX 1.5 JSON bill of materials.

## What it catches in practice

Tested against the deliberately vulnerable demo server that ships with
the repo, the fuzzer found in <10 seconds:

- Command injection: `$(whoami)` returns `uid=501(cat)`
- Path traversal: `../../etc/passwd` returns the file
- SSRF: `file://` protocol leaks `/etc/passwd`

These are the exact bugs static-only scanners miss.

## Try it

```
pip install git+https://github.com/test008008008008-glitch/mcp-cateye.git
mcp-cateye fuzz python -- -m mcp_cateye.vuln_server
mcp-cateye scan . --aibom
```

MIT-licensed, ~800 LOC, 40 tests passing. Issues + PRs welcome.

Happy to answer questions about design decisions, false-positive tuning,
or how the fuzzer works under the hood.
```

---

## 3. Twitter/X Thread

**Thread** (8 tweets):

```
1/ Built an open-source MCP security scanner. It actually fuzzes —
spawns the server and probes it with attack payloads, instead of just
reading source code.

GitHub: https://github.com/test008008008008-glitch/mcp-cateye
MIT, ~800 LOC, 40 tests 🧵

2/ Why I built it: I kept auditing MCP servers and finding cmd
injection bugs that existing tools missed. They each do one thing
well — static analysis, config scanning, or poisoning detection —
but none of them probe the live server.

3/ mcp-cateye does four things in one CLI:
- Active fuzzing (50+ payloads, 9 categories)
- Static analysis (configs, secrets, dependencies, AST readiness)
- Security scoring (0-100 + A-F grade)
- AI-BOM (CycloneDX 1.5 JSON)

4/ The fuzzer part: spawns the MCP server via stdio, enumerates its
tools, then mutates each parameter with attack payloads and inspects
the response. Caught real bugs in <10s on the demo vulnerable server:
- `$(whoami)` → returned `uid=501(cat)`
- `../../etc/passwd` → leaked the file
- `file://` → SSRF

5/ The static part (v1.1.0):
- Config discovery (Claude/Cursor/VS Code/Windsurf/Zed)
- Secrets (OpenAI/GitHub/AWS/JWT regex)
- Tool description poisoning (rug pull detection)
- pip-audit for dep CVEs
- AST-based readiness checks

6/ One CLI, zero blind spots. Static-only scanners miss cmd
injection. Fuzzers miss hardcoded secrets. cateye catches both in
one scan.

7/ Install:
pip install git+https://github.com/test008008008008-glitch/mcp-cateye.git

Try the demo:
mcp-cateye fuzz python -- -m mcp_cateye.vuln_server

8/ Looking for contributors! Specifically:
- More payload categories
- YARA rule integration
- False-positive tuning for AI-generated servers

Issues + PRs welcome 🐱
```

---

## 4. dev.to / Medium Long-Form Article

**Title**: Building mcp-cateye: Why MCP Security Needs Active Fuzzing, Not Just Static Analysis

**Outline**:
1. The gap I noticed: command-injection bugs that every existing MCP
   security tool missed
2. Why I built a tool that does all four kinds of analysis
3. How the fuzzer works (stdio spawn, tool enumeration, mutation,
   detection)
4. What the demo vulnerable server caught in <10s
5. The static analysis engine (config discovery, secrets, deps, AST)
6. Security scoring + AI-BOM
7. Try it / contribute

**Length**: 1500-2000 words. English, technical but accessible.
**Tags**: security, mcp, ai, fuzzing, python, opensource

---

## POSTING CHECKLIST

Before posting, do these manually:

### Hacker News (https://news.ycombinator.com/submit)
- [ ] Login to HN
- [ ] Submit "Show HN" with the title above
- [ ] URL: https://github.com/test008008008008-glitch/mcp-cateye
- [ ] Add the extra text in "text" field
- [ ] After posting, monitor for comments and respond quickly

### Reddit r/netsec (https://www.reddit.com/r/netsec/submit)
- [ ] Login to Reddit
- [ ] Go to r/netsec → Submit
- [ ] Use a text/link post
- [ ] Use the title + body above
- [ ] **IMPORTANT**: r/netsec is strict about self-promotion. Lead with technical
      value, not "I built this". Frame it as "sharing a tool I built because
      the gap needed filling" not "check out my new project"

### Twitter/X
- [ ] Post the thread above
- [ ] Pin the first tweet for 48 hours
- [ ] Use image cards for install command and demo output

### dev.to
- [ ] Login to dev.to
- [ ] Write the long-form article
- [ ] Tag: #security #mcp #ai #python #fuzzing
- [ ] Cross-link to HN/Reddit posts for engagement

### Lobsters (https://lobste.rs/)
- [ ] Invite-only or by tag suggestion
- [ ] Skip for now unless user wants

### Product Hunt
- [ ] Needs a "maker" account, scheduled launch
- [ ] Can do later (not high-priority for dev tool)

---

## TIMING

Best post times (US East Coast):
- HN: weekday morning 8-10am ET
- Reddit r/netsec: weekday morning
- Twitter: any time, but the first tweet pinned for visibility

Avoid weekends for HN/Reddit.
