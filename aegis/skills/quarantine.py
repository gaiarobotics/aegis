"""Static code analysis for skill quarantine decisions."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field


@dataclass
class AnalysisFinding:
    """A single finding from static analysis."""

    pattern: str
    description: str
    severity: float
    line_number: int | None = None


@dataclass
class AnalysisResult:
    """Aggregated result of static code analysis."""

    findings: list[AnalysisFinding] = field(default_factory=list)
    risk_score: float = 0.0
    safe: bool = True


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
_SEVERITY_EXEC = 0.5
_SEVERITY_EVAL = 0.5
_SEVERITY_SUBPROCESS = 0.5
_SEVERITY_OS_SYSTEM = 0.5
_SEVERITY_OS_POPEN = 0.5
_SEVERITY_DUNDER_IMPORT = 0.4
_SEVERITY_OPEN_WRITE = 0.3
_SEVERITY_SHELL_HIGH = 0.5

_HIGH_SEVERITY_THRESHOLD = 0.4


# ---------------------------------------------------------------------------
# Python AST-based analysis
# ---------------------------------------------------------------------------

class _DangerousPatternVisitor(ast.NodeVisitor):
    """Walk a Python AST looking for dangerous patterns."""

    def __init__(self) -> None:
        self.findings: list[AnalysisFinding] = []

    # -- exec() / eval() calls ------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # Direct call: exec(...) or eval(...)
        if isinstance(func, ast.Name) and func.id in ("exec", "eval"):
            self.findings.append(
                AnalysisFinding(
                    pattern=func.id,
                    description=f"Use of {func.id}() detected",
                    severity=_SEVERITY_EXEC if func.id == "exec" else _SEVERITY_EVAL,
                    line_number=node.lineno,
                )
            )

        # Attribute call: subprocess.run, subprocess.Popen, subprocess.call
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                if func.attr in ("run", "Popen", "call"):
                    self.findings.append(
                        AnalysisFinding(
                            pattern=f"subprocess.{func.attr}",
                            description=f"Use of subprocess.{func.attr}() detected",
                            severity=_SEVERITY_SUBPROCESS,
                            line_number=node.lineno,
                        )
                    )

            # os.system / os.popen
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                if func.attr == "system":
                    self.findings.append(
                        AnalysisFinding(
                            pattern="os.system",
                            description="Use of os.system() detected",
                            severity=_SEVERITY_OS_SYSTEM,
                            line_number=node.lineno,
                        )
                    )
                elif func.attr == "popen":
                    self.findings.append(
                        AnalysisFinding(
                            pattern="os.popen",
                            description="Use of os.popen() detected",
                            severity=_SEVERITY_OS_POPEN,
                            line_number=node.lineno,
                        )
                    )

        # __import__('dangerous_module')
        if isinstance(func, ast.Name) and func.id == "__import__":
            if node.args and isinstance(node.args[0], ast.Constant):
                module_name = node.args[0].value
                dangerous_modules = {"os", "subprocess", "shutil", "ctypes", "socket"}
                if module_name in dangerous_modules:
                    self.findings.append(
                        AnalysisFinding(
                            pattern=f"__import__({module_name})",
                            description=f"Dynamic import of dangerous module: {module_name}",
                            severity=_SEVERITY_DUNDER_IMPORT,
                            line_number=node.lineno,
                        )
                    )

        # open() with write modes
        if isinstance(func, ast.Name) and func.id == "open":
            write_modes = {"w", "a", "x", "wb", "ab", "xb", "w+", "a+", "r+",
                           "w+b", "a+b", "r+b"}
            # Check second positional arg or 'mode' keyword arg
            mode_value = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode_value = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode_value = kw.value.value
            if mode_value and mode_value in write_modes:
                self.findings.append(
                    AnalysisFinding(
                        pattern=f"open(mode={mode_value})",
                        description=f"File open with write mode '{mode_value}' detected",
                        severity=_SEVERITY_OPEN_WRITE,
                        line_number=node.lineno,
                    )
                )

        self.generic_visit(node)


def _analyze_python(code: str) -> list[AnalysisFinding]:
    """Analyze Python code using the ast module."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [
            AnalysisFinding(
                pattern="syntax_error",
                description="Code could not be parsed (syntax error)",
                severity=0.2,
                line_number=None,
            )
        ]

    visitor = _DangerousPatternVisitor()
    visitor.visit(tree)
    return visitor.findings


# ---------------------------------------------------------------------------
# Shell regex-based analysis
# ---------------------------------------------------------------------------

_SHELL_PATTERNS: list[tuple[str, str, float]] = [
    (r"rm\s+-[^\s]*r[^\s]*f|rm\s+-[^\s]*f[^\s]*r|rm\s+-rf", "rm -rf detected", _SEVERITY_SHELL_HIGH),
    (r"curl\s[^|]*\|\s*bash", "curl | bash pipe detected", _SEVERITY_SHELL_HIGH),
    (r"curl\s[^|]*\|\s*sh", "curl | sh pipe detected", _SEVERITY_SHELL_HIGH),
    (r"wget\s[^|]*\|\s*bash", "wget | bash pipe detected", _SEVERITY_SHELL_HIGH),
    (r"wget\s[^|]*\|\s*sh", "wget | sh pipe detected", _SEVERITY_SHELL_HIGH),
]


def _analyze_shell(code: str) -> list[AnalysisFinding]:
    """Analyze shell code using regex-based pattern matching."""
    findings: list[AnalysisFinding] = []
    lines = code.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        for pattern_re, description, severity in _SHELL_PATTERNS:
            if re.search(pattern_re, line):
                findings.append(
                    AnalysisFinding(
                        pattern=pattern_re,
                        description=description,
                        severity=severity,
                        line_number=line_idx,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_code(code: str, language: str = "python") -> AnalysisResult:
    """Perform static analysis on the given code.

    For Python code, uses the ast module to detect dangerous patterns:
    - exec() and eval() calls
    - subprocess usage (subprocess.run, subprocess.Popen, subprocess.call)
    - os.system, os.popen
    - __import__ of dangerous modules
    - open() with write modes

    For shell code, uses regex-based detection of dangerous patterns:
    - rm -rf
    - curl | bash, curl | sh
    - wget | bash, wget | sh

    Args:
        code: Source code to analyze.
        language: Language of the code ("python" or "shell").

    Returns:
        An AnalysisResult with findings, risk_score, and safe flag.
    """
    if language == "python":
        findings = _analyze_python(code)
    elif language == "shell":
        findings = _analyze_shell(code)
    else:
        findings = []

    risk_score = min(sum(f.severity for f in findings), 1.0)
    has_high_severity = any(f.severity >= _HIGH_SEVERITY_THRESHOLD for f in findings)
    safe = risk_score < 0.3 and not has_high_severity

    return AnalysisResult(
        findings=findings,
        risk_score=risk_score,
        safe=safe,
    )
