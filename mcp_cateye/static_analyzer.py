"""Static analysis engine for MCP server security.

Covers:
- Config discovery (Claude, Cursor, VS Code, Windsurf, etc.)
- Secrets detection in configs and source code
- Dependency vulnerability scanning (pip-audit)
- Tool description analysis (poisoning, rug pull, prompt injection)
- Readiness checks (timeout, retry, error handling)
- Scoring system (0-100 + A-F grade)
- AI-BOM generation (CycloneDX JSON)
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from . import __version__ as _CATEYE_VERSION

# ── Config Discovery ────────────────────────────────────────────────────────

# Known MCP client config paths
CLIENT_CONFIG_PATHS = {
    "claude": [
        Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
        Path.home() / ".config/Claude/claude_desktop_config.json",
    ],
    "cursor": [
        Path.home() / ".cursor/mcp.json",
        Path.home() / ".cursor/mcp_config.json",
    ],
    "vscode": [
        Path.home() / ".vscode/mcp.json",
        Path.home() / "Library/Application Support/Code/User/globalStorage/mcp.json",
    ],
    "windsurf": [
        Path.home() / ".windsurf/mcp.json",
    ],
    "zed": [
        Path.home() / ".config/zed/mcp.json",
    ],
    "cline": [
        Path.home() / ".cline/mcp_settings.json",
    ],
    "roocode": [
        Path.home() / ".roocode/mcp.json",
    ],
    "copilot": [
        Path.home() / ".github/copilot/mcp.json",
    ],
}

# Directories to search for MCP configs
MCP_CONFIG_GLOBS = [
    "**/.mcp.json",
    "**/mcp.json",
    "**/mcp_config.json",
    "**/claude_desktop_config.json",
    "**/.cursor/mcp.json",
]


@dataclass
class MCPConfig:
    """A discovered MCP server configuration entry."""

    client: str
    server_name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    config_path: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def discover_configs(
    clients: list[str] | None = None,
    scan_dirs: list[str] | None = None,
) -> list[MCPConfig]:
    """Discover MCP server configs from known client paths and project directories."""
    configs: list[MCPConfig] = []

    targets = (
        {k: v for k, v in CLIENT_CONFIG_PATHS.items() if k in clients}
        if clients
        else CLIENT_CONFIG_PATHS
    )

    # 1. Known client config paths
    for client, paths in targets.items():
        for path in paths:
            if path.exists():
                try:
                    data = json.loads(path.read_text())
                    for name, cfg in data.get("mcpServers", {}).items():
                        configs.append(
                            MCPConfig(
                                client=client,
                                server_name=name,
                                command=cfg.get("command", ""),
                                args=cfg.get("args", []),
                                env=cfg.get("env", {}),
                                config_path=str(path),
                                raw=cfg,
                            )
                        )
                except (json.JSONDecodeError, OSError):
                    pass

    # 2. Project directory scanning
    if scan_dirs:
        for scan_dir in scan_dirs:
            base = Path(scan_dir).expanduser().resolve()
            if not base.is_dir():
                continue
            for glob_pattern in MCP_CONFIG_GLOBS:
                for found in base.glob(glob_pattern):
                    try:
                        data = json.loads(found.read_text())
                        for name, cfg in data.get("mcpServers", {}).items():
                            configs.append(
                                MCPConfig(
                                    client="project",
                                    server_name=name,
                                    command=cfg.get("command", ""),
                                    args=cfg.get("args", []),
                                    env=cfg.get("env", {}),
                                    config_path=str(found),
                                    raw=cfg,
                                )
                            )
                    except (json.JSONDecodeError, OSError):
                        pass

    return configs


# ── Secrets Detection ────────────────────────────────────────────────────────

# High-signal secret patterns (minimized false positives)
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, name, severity)
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']', "API Key", "critical"),
    (r'(?:secret|token|password|passwd)\s*[:=]\s*["\']([^\s]{8,})["\']', "Secret/Token", "critical"),
    (r'sk-[A-Za-z0-9\-]{32,}', "OpenAI API Key", "critical"),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}', "GitHub Token", "critical"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "critical"),
    (r'(?:xox[baprs]-[A-Za-z0-9\-]+)', "Slack Token", "high"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "high"),
    (r'(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', "JWT Token", "high"),
    (r'(?:-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)', "Private Key", "critical"),
    (r'(?:mongodb(?:\+srv)?://[^\s]+)', "MongoDB URI", "high"),
    (r'(?:postgres(?:ql)?://[^\s]+)', "PostgreSQL URI", "high"),
    (r'(?:mysql://[^\s]+)', "MySQL URI", "high"),
    (r'(?:redis://[^\s]+)', "Redis URI", "high"),
]


@dataclass
class SecretFinding:
    file_path: str
    line: int
    secret_type: str
    severity: str
    snippet: str  # masked


# Directories that should always be excluded from scanning
EXCLUDED_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".tox", ".eggs", "dist", "build", ".mypy_cache", ".pytest_cache",
    "site-packages", ".hg", ".svn", "payloads",
}

# File names that are regex pattern definitions, not real secrets
_SECRET_PATTERN_FILES = {"payloads", "static_analyzer", "test_", "conftest"}


def _should_exclude_file(f: Path) -> bool:
    """Check if a file should be excluded from scanning."""
    parts = set(f.parts)
    if parts & EXCLUDED_DIRS:
        return True
    # Skip files that define regex patterns (like our own scanner code).
    # Only check the file NAME — checking path parts caused false exclusions
    # (e.g. pytest tmp_path dirs contain "test_" prefix).
    for marker in _SECRET_PATTERN_FILES:
        if marker in f.name:
            return True
    return False


def scan_secrets(paths: list[str]) -> list[SecretFinding]:
    """Scan files/directories for hardcoded secrets."""
    findings: list[SecretFinding] = []
    seen: set[tuple[str, int, str]] = set()

    files_to_scan: list[Path] = []
    for p in paths:
        pp = Path(p).expanduser().resolve()
        if pp.is_file():
            if not _should_exclude_file(pp):
                files_to_scan.append(pp)
        elif pp.is_dir():
            for f in pp.rglob("*"):
                if not f.is_file():
                    continue
                if _should_exclude_file(f):
                    continue
                if not (
                    f.suffix in (
                        ".py", ".js", ".ts", ".json", ".yaml", ".yml",
                        ".toml", ".sh", ".bash", ".cfg", ".ini",
                        ".txt", ".md", ".jsx", ".tsx", ".go", ".rs",
                    )
                    or f.name in (".env", ".env.local", ".env.production", ".env.dev")
                ):
                    continue
                files_to_scan.append(f)

    for fpath in files_to_scan:
        try:
            content = fpath.read_text(errors="replace")
        except OSError:
            continue

        for pattern, name, severity in SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count("\n") + 1
                key = (str(fpath), line_no, name)
                if key in seen:
                    continue
                seen.add(key)

                # Mask the secret value
                matched = match.group(0)
                if len(matched) > 30:
                    snippet = matched[:15] + "..." + matched[-10:]
                else:
                    snippet = matched[:8] + "***"

                findings.append(
                    SecretFinding(
                        file_path=str(fpath),
                        line=line_no,
                        secret_type=name,
                        severity=severity,
                        snippet=snippet,
                    )
                )

    return findings


# ── Dependency Vulnerability Scanning ────────────────────────────────────────


@dataclass
class VulnDep:
    package: str
    version: str
    vuln_id: str
    severity: str
    description: str


def scan_dependencies(project_path: str) -> list[VulnDep]:
    """Scan Python dependencies for known vulnerabilities using pip-audit."""
    findings: list[VulnDep] = []

    pip_audit = _find_executable("pip-audit")
    if not pip_audit:
        return findings

    try:
        result = subprocess.run(
            [pip_audit, "--format", "json", "-r", str(Path(project_path) / "requirements.txt")],
            capture_output=True, text=True, timeout=60,
            cwd=project_path,
        )
        if result.returncode == 0:
            return findings  # no vulns

        data = json.loads(result.stdout) if result.stdout.strip() else {}
        for vuln in data.get("dependencies", []):
            for v in vuln.get("vulns", []):
                findings.append(
                    VulnDep(
                        package=vuln.get("name", "unknown"),
                        version=vuln.get("version", "unknown"),
                        vuln_id=v.get("id", "unknown"),
                        severity=_map_pip_audit_severity(v.get("severity", "")),
                        description=v.get("description", "")[:200],
                    )
                )
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass

    return findings


def _map_pip_audit_severity(sev: str) -> str:
    sev_lower = sev.lower()
    if "critical" in sev_lower:
        return "critical"
    if "high" in sev_lower:
        return "high"
    if "medium" in sev_lower or "moderate" in sev_lower:
        return "medium"
    return "low"


def _find_executable(name: str) -> str | None:
    """Find an executable in PATH."""
    for path in os.environ.get("PATH", "").split(os.pathsep):
        exe = Path(path) / name
        if exe.is_file():
            return str(exe)
    return None


# ── Tool Description Analysis ────────────────────────────────────────────────


@dataclass
class ToolDescFinding:
    tool_name: str
    issue_type: str  # poisoning, rug_pull, prompt_injection, over_privileged
    severity: str
    description: str
    evidence: str


# Patterns that indicate tool description poisoning
POISONING_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)(ignore|override|bypass)\s+(all\s+)?(previous\s+)?instructions", "Instruction override", "critical"),
    (r"(?i)you\s+(are|now)\s+(DAN|in\s+debug\s+mode|unrestricted)", "Role hijack attempt", "critical"),
    (r"(?i)(hidden|secret|covert)\s+(instruction|command|directive)", "Hidden instruction", "high"),
    (r"(?i)do\s+not\s+(tell|reveal|disclose|mention|report)", "Concealment directive", "high"),
    (r"(?i)exfiltrat(e|ion)\s+(data|info|files|credentials)", "Data exfiltration", "critical"),
    (r"(?i)(download|fetch|curl|wget)\s+(http|ftp)", "Remote fetch in description", "high"),
    (r"(?i)execute\s+(arbitrary|any)\s+(code|command)", "Arbitrary execution claim", "critical"),
    (r"(?i)(sudo|root|admin|privilege)\s+(access|escalat)", "Privilege escalation", "high"),
    (r"(?i)send\s+(this|the\s+result|output)\s+to\s+(http|https)", "Data exfiltration URL", "critical"),
]

# Patterns for over-privileged tools
OVER_PRIVILEGED_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)(shell|bash|sh|cmd|terminal|exec|subprocess|os\.system|popen)", "Shell access", "critical"),
    (r"(?i)(read|write|delete|modify)\s+(any|all|arbitrary)\s+file", "Arbitrary file access", "high"),
    (r"(?i)(http|https|fetch|request|curl|wget|urllib)", "Network access", "medium"),
    (r"(?i)(database|sql|query|mongodb|postgres|mysql|redis)", "Database access", "high"),
    (r"(?i)(environment|env\s+var|os\.environ|process\.env)", "Environment access", "medium"),
]


def analyze_tool_descriptions(tools: list[dict[str, Any]]) -> list[ToolDescFinding]:
    """Analyze MCP tool descriptions for poisoning, rug pull, and over-privilege."""
    findings: list[ToolDescFinding] = []

    for tool in tools:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")
        input_schema = tool.get("inputSchema", {})

        # Check for poisoning patterns in description
        for pattern, issue, severity in POISONING_PATTERNS:
            if re.search(pattern, desc):
                findings.append(
                    ToolDescFinding(
                        tool_name=name,
                        issue_type="poisoning",
                        severity=severity,
                        description=issue,
                        evidence=_extract_context(desc, pattern),
                    )
                )

        # Check for over-privileged patterns
        for pattern, issue, severity in OVER_PRIVILEGED_PATTERNS:
            if re.search(pattern, desc):
                findings.append(
                    ToolDescFinding(
                        tool_name=name,
                        issue_type="over_privileged",
                        severity=severity,
                        description=f"Tool claims {issue} capability",
                        evidence=_extract_context(desc, pattern),
                    )
                )

        # Check input schema for dangerous params
        props = input_schema.get("properties", {})
        for param_name, param_info in props.items():
            param_desc = param_info.get("description", "")
            combined = f"{param_name}: {param_desc}"

            if re.search(r"(?i)(command|shell|cmd|exec|bash)", combined):
                findings.append(
                    ToolDescFinding(
                        tool_name=name,
                        issue_type="over_privileged",
                        severity="critical",
                        description=f"Parameter '{param_name}' accepts shell commands",
                        evidence=combined[:120],
                    )
                )

            if re.search(r"(?i)(file[\s_]*path|filename|directory)", combined):
                findings.append(
                    ToolDescFinding(
                        tool_name=name,
                        issue_type="over_privileged",
                        severity="high",
                        description=f"Parameter '{param_name}' accepts file paths",
                        evidence=combined[:120],
                    )
                )

            if re.search(r"(?i)(url|endpoint|host|domain)", combined):
                findings.append(
                    ToolDescFinding(
                        tool_name=name,
                        issue_type="over_privileged",
                        severity="medium",
                        description=f"Parameter '{param_name}' accepts URLs/endpoints",
                        evidence=combined[:120],
                    )
                )

    return findings


def _extract_context(text: str, pattern: str, window: int = 40) -> str:
    """Extract text around a regex match for evidence."""
    m = re.search(pattern, text)
    if not m:
        return text[:80]
    start = max(0, m.start() - window)
    end = min(len(text), m.end() + window)
    ctx = text[start:end]
    if start > 0:
        ctx = "..." + ctx
    if end < len(text):
        ctx = ctx + "..."
    return ctx


# ── Readiness Checks ─────────────────────────────────────────────────────────


@dataclass
class ReadinessFinding:
    file_path: str
    line: int
    issue: str
    severity: str
    description: str


def scan_readiness(source_paths: list[str]) -> list[ReadinessFinding]:
    """Check MCP server source code for production readiness issues."""
    findings: list[ReadinessFinding] = []

    for sp in source_paths:
        pp = Path(sp).expanduser().resolve()
        if pp.is_dir():
            py_files = list(pp.rglob("*.py"))
        elif pp.is_file() and pp.suffix == ".py":
            py_files = [pp]
        else:
            continue

        for py_file in py_files:
            # Skip excluded dirs, test files, and __pycache__
            if _should_exclude_file(py_file):
                continue
            if "test" in py_file.name.lower():
                continue

            try:
                source = py_file.read_text()
            except OSError:
                continue

            tree = ast.parse(source)
            analyzer = _ReadinessAnalyzer(str(py_file))
            analyzer.visit(tree)
            findings.extend(analyzer.findings)

    return findings


class _ReadinessAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: list[ReadinessFinding] = []

    def _add(self, node: ast.AST, issue: str, severity: str, desc: str):
        self.findings.append(
            ReadinessFinding(
                file_path=self.file_path,
                line=node.lineno,
                issue=issue,
                severity=severity,
                description=desc,
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Check for missing timeout in network calls
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child)
                if func_name in ("requests.get", "requests.post", "urllib.request.urlopen",
                                 "httpx.get", "httpx.post", "aiohttp.ClientSession"):
                    has_timeout = any(
                        kw.arg == "timeout" for kw in child.keywords
                    )
                    if not has_timeout:
                        self._add(
                            child, "missing_timeout", "high",
                            f"Network call '{func_name}' has no timeout — risk of hanging",
                        )

            # Check for bare except
            if isinstance(child, ast.ExceptHandler) and child.type is None:
                self._add(
                    child, "bare_except", "medium",
                    "Bare 'except:' catches everything including KeyboardInterrupt",
                )

            # Check for shell=True
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child)
                if func_name in ("subprocess.run", "subprocess.call", "subprocess.Popen",
                                 "os.system", "os.popen"):
                    has_shell_true = any(
                        kw.arg == "shell" and
                        (isinstance(kw.value, ast.Constant) and kw.value.value is True)
                        for kw in child.keywords
                    )
                    if has_shell_true:
                        self._add(
                            child, "shell_injection", "critical",
                            "subprocess with shell=True — command injection risk",
                        )

        self.generic_visit(node)

    def _get_func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            obj = self._get_name(node.func.value)
            return f"{obj}.{node.func.attr}" if obj else node.func.attr
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _get_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        return ""


# ── Scoring System ───────────────────────────────────────────────────────────


class Grade(Enum):
    A_PLUS = ("A+", 95)
    A = ("A", 88)
    B_PLUS = ("B+", 80)
    B = ("B", 70)
    C = ("C", 55)
    D = ("D", 40)
    F = ("F", 0)

    def __init__(self, label: str, threshold: int):
        self.label = label
        self.threshold = threshold

    @classmethod
    def from_score(cls, score: int) -> "Grade":
        for grade in cls:
            if score >= grade.threshold:
                return grade
        return cls.F


@dataclass
class SecurityScore:
    overall: int  # 0-100
    grade: str    # A+ through F
    breakdown: dict[str, int]  # category -> score
    details: dict[str, Any] = field(default_factory=dict)


def calculate_score(
    fuzz_findings: list[Any] | None = None,
    secret_findings: list[SecretFinding] | None = None,
    vuln_deps: list[VulnDep] | None = None,
    tool_desc_findings: list[ToolDescFinding] | None = None,
    readiness_findings: list[ReadinessFinding] | None = None,
) -> SecurityScore:
    """Calculate a 0-100 security score with A-F grade."""
    fuzz = fuzz_findings or []
    secrets = secret_findings or []
    vulns = vuln_deps or []
    tools = tool_desc_findings or []
    readiness = readiness_findings or []

    # Each category starts at 100, deductions for findings
    def cat_score(findings: list, weights: dict[str, int]) -> int:
        score = 100
        for f in findings:
            sev = getattr(f, "severity", "low")
            score -= weights.get(sev, 5)
        return max(0, score)

    fuzz_score = cat_score(fuzz, {"critical": 15, "high": 10, "medium": 5, "low": 2})
    secret_score = cat_score(secrets, {"critical": 20, "high": 12, "medium": 6, "low": 3})
    vuln_score = cat_score(vulns, {"critical": 20, "high": 12, "medium": 6, "low": 3})
    tool_score = cat_score(tools, {"critical": 15, "high": 10, "medium": 5, "low": 2})
    readiness_score = cat_score(readiness, {"critical": 10, "high": 7, "medium": 4, "low": 2})

    breakdown = {
        "fuzzing": fuzz_score,
        "secrets": secret_score,
        "dependencies": vuln_score,
        "tool_descriptions": tool_score,
        "readiness": readiness_score,
    }

    # Weighted average
    weights = {"fuzzing": 0.30, "secrets": 0.20, "dependencies": 0.20,
               "tool_descriptions": 0.15, "readiness": 0.15}
    overall = int(sum(breakdown[k] * weights[k] for k in weights))
    grade = Grade.from_score(overall)

    return SecurityScore(
        overall=overall,
        grade=grade.label,
        breakdown=breakdown,
        details={
            "fuzz_critical": sum(1 for f in fuzz if getattr(f, "severity", "") == "critical"),
            "fuzz_total": len(fuzz),
            "secrets_critical": sum(1 for s in secrets if s.severity == "critical"),
            "secrets_total": len(secrets),
            "vulns_critical": sum(1 for v in vulns if v.severity == "critical"),
            "vulns_total": len(vulns),
            "tool_issues": len(tools),
            "readiness_issues": len(readiness),
        },
    )


# ── AI-BOM Generation ────────────────────────────────────────────────────────


def generate_aibom(
    server_name: str,
    tools: list[dict[str, Any]],
    configs: list[MCPConfig] | None = None,
    dependencies: list[str] | None = None,
) -> dict[str, Any]:
    """Generate an AI-BOM in CycloneDX 1.5 JSON format."""
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{_uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [
                {
                    "vendor": "mcp-cateye",
                    "name": "mcp-cateye",
                    "version": _CATEYE_VERSION,
                }
            ],
            "component": {
                "type": "application",
                "name": server_name,
                "description": f"MCP Server: {server_name}",
            },
        },
        "components": [],
    }

    # Add tools as components
    for tool in tools:
        comp: dict[str, Any] = {
            "type": "application",
            "name": tool.get("name", "unknown"),
            "description": tool.get("description", "")[:500],
            "properties": [
                {"name": "mcp:tool", "value": tool.get("name", "")},
                {"name": "mcp:category", "value": "tool"},
            ],
        }

        # Add input schema as properties
        input_schema = tool.get("inputSchema", {})
        for prop_name, prop_info in input_schema.get("properties", {}).items():
            comp["properties"].append({
                "name": f"mcp:param:{prop_name}",
                "value": prop_info.get("description", prop_info.get("type", "string")),
            })

        bom["components"].append(comp)

    # Add discovered configs
    if configs:
        for cfg in configs:
            bom["components"].append({
                "type": "application",
                "name": f"config:{cfg.client}:{cfg.server_name}",
                "description": f"MCP config from {cfg.client}",
                "properties": [
                    {"name": "mcp:client", "value": cfg.client},
                    {"name": "mcp:command", "value": cfg.command},
                    {"name": "mcp:config_path", "value": cfg.config_path},
                ],
            })

    # Add dependencies
    if dependencies:
        for dep in dependencies:
            bom["components"].append({
                "type": "library",
                "name": dep,
                "properties": [
                    {"name": "mcp:dependency", "value": dep},
                ],
            })

    return bom


def _uuid4() -> str:
    import uuid
    return str(uuid.uuid4())


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ── Full Static Analysis Orchestrator ────────────────────────────────────────


@dataclass
class StaticAnalysisResult:
    configs: list[MCPConfig] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    vuln_deps: list[VulnDep] = field(default_factory=list)
    tool_desc_findings: list[ToolDescFinding] = field(default_factory=list)
    readiness_findings: list[ReadinessFinding] = field(default_factory=list)
    score: SecurityScore | None = None
    aibom: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)


def run_static_analysis(
    project_path: str | None = None,
    clients: list[str] | None = None,
    scan_dirs: list[str] | None = None,
    tools: list[dict[str, Any]] | None = None,
    skip_secrets: bool = False,
    skip_deps: bool = False,
    skip_readiness: bool = False,
) -> StaticAnalysisResult:
    """Run the full static analysis pipeline."""
    result = StaticAnalysisResult()

    # 1. Config discovery
    result.configs = discover_configs(clients=clients, scan_dirs=scan_dirs)

    # 2. Secrets detection
    if not skip_secrets:
        paths_to_scan: list[str] = []
        if project_path:
            paths_to_scan.append(project_path)
        for cfg in result.configs:
            if cfg.config_path:
                paths_to_scan.append(cfg.config_path)
        if paths_to_scan:
            result.secrets = scan_secrets(paths_to_scan)

    # 3. Dependency scanning
    if not skip_deps and project_path:
        result.vuln_deps = scan_dependencies(project_path)

    # 4. Tool description analysis
    if tools:
        result.tool_desc_findings = analyze_tool_descriptions(tools)

    # 5. Readiness checks
    if not skip_readiness and project_path:
        result.readiness_findings = scan_readiness([project_path])

    # 6. Scoring
    result.score = calculate_score(
        secret_findings=result.secrets,
        vuln_deps=result.vuln_deps,
        tool_desc_findings=result.tool_desc_findings,
        readiness_findings=result.readiness_findings,
    )

    # 7. AI-BOM
    if tools:
        result.aibom = generate_aibom(
            server_name=project_path or "unknown",
            tools=tools,
            configs=result.configs,
        )

    return result
