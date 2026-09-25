"""项目文件静态安全审计（白盒层）：对一个 AGENT 项目的源码与配置做规则扫描。

与对话扫描（黑盒）互补：不需要目标运行、不需要任何接口，直接审计项目文件。
检测维度（均为规则命中，证据 = 文件:行号 + 真实行内容）：
- 凭据与密钥：sk-/AKIA/ghp_/私钥块/JWT/key=value 形式凭据硬编码
- 提示词卫生：系统提示词文件中包含敏感凭据（系统提示词可被逐字泄露，见 leak 模块）
- 危险执行：eval/exec、os.system/popen、subprocess shell=True、命令 f-string 拼接
- 反序列化：pickle、未指定安全 Loader 的 yaml.load
- SQL 拼接：execute() 中拼接 SQL 语句
- 文件边界：open() 使用动态路径（提示人工确认路径校验）
- 外发通道：明文 http 出站、已知外发/收集端点
- 结构化检查：MCP 配置（复用 mcp-scan 静态审计）、.env 凭据、依赖未固定版本
"""

import json
import os
import re
from pathlib import Path
from typing import Callable, Optional

from . import mcp_scan

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "dist", "build",
             ".pytest_cache", ".mypy_cache", ".idea", ".vscode", "egg-info", ".tox"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tar",
              ".exe", ".dll", ".so", ".dylib", ".pyc", ".class", ".woff", ".woff2", ".ttf",
              ".mp3", ".mp4", ".avi", ".bin", ".db", ".sqlite", ".onnx", ".gguf", ".safetensors"}

EXFIL_RE = mcp_scan.EXFIL_ENDPOINTS_RE

# 行级规则：(rule_id, severity, title, compiled regex)
RULES: list[tuple] = [
    ("SEC-SK", "high", "疑似 OpenAI 风格密钥硬编码（sk-...）",
     re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("SEC-AWS", "high", "疑似 AWS Access Key 硬编码（AKIA...）",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SEC-GHP", "high", "疑似 GitHub PAT 硬编码（ghp_...）",
     re.compile(r"\bghp_[A-Za-z0-9]{20,}")),
    ("SEC-PRIVKEY", "high", "私钥块硬编码",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("SEC-KEYVAL", "high", "代码/配置中出现 key=value 形式凭据",
     re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
    ("SEC-KEYVAL-UNQ", "high", "凭据以未加引号的 key=value 形式硬编码",
     re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*[A-Za-z0-9_+\-/]{12,}")),
    ("SEC-JWT", "medium", "JWT 令牌硬编码",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}")),
    ("EXEC-EVAL", "high", "使用 eval()（动态代码执行）",
     re.compile(r"\beval\s*\(")),
    ("EXEC-EXEC", "high", "使用 exec()（动态代码执行）",
     re.compile(r"\bexec\s*\(")),
    ("EXEC-OSSYSTEM", "high", "os.system / os.popen（命令注入面）",
     re.compile(r"\bos\.(system|popen)\s*\(")),
    ("EXEC-SUBSHELL", "high", "subprocess 以 shell=True 运行",
     re.compile(r"shell\s*=\s*True")),
    ("EXEC-CONCAT", "high", "命令字符串拼接（f-string 直接进 shell/命令）",
     re.compile(r"(os\.system|os\.popen|subprocess\.\w+)\s*\(\s*f['\"]")),
    ("DESER-PICKLE", "high", "反序列化不可信数据（pickle）",
     re.compile(r"\bpickle\.loads?\s*\(")),
    ("DESER-YAML", "high", "yaml.load 未指定安全 Loader",
     re.compile(r"yaml\.load\s*\((?![^)]*Loader\s*=)")),
    ("SQL-CONCAT", "high", "SQL 语句拼接（疑似注入面）",
     re.compile(r"execute\s*\(\s*f['\"]|execute\s*\(\s*['\"][^'\"]*\b(select|insert|update|delete)\b[^'\"]*['\"]\s*\+", re.I)),
    ("PATH-OPENVAR", "medium", "open() 使用动态路径（请确认是否做了路径校验）",
     re.compile(r"\bopen\s*\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*[,)]")),
    ("NET-HTTP", "medium", "明文 http 出站地址",
     re.compile(r"\bhttp://(?!127\.0\.0\.1|localhost)")),
    ("NET-EXFIL", "high", "包含已知外发/收集端点", EXFIL_RE),
]

# 提示词文件特征（内容级）
PROMPT_MARK_RE = re.compile(r"(you are|your role|你是|你是一名|系统提示|system prompt|persona)", re.I)
# 依赖声明中已知需要留意的包（示例性黑名单，可扩展）
RISKY_PACKAGES = {"eval", "pickle5", "pyyaml"}


def _safe_path(p: str) -> str:
    """路径规范化校验：展开用户目录、折叠相对段，拒绝残留父目录穿越段。"""
    norm = os.path.abspath(os.path.expanduser(p))
    if os.pardir in norm.split(os.sep) or norm.strip() in ("", os.sep):
        raise SystemExit(f"非法路径: {p}")
    return norm


def _write_text(out: str, content: str) -> str:
    """把报告文本写到已校验的输出路径。"""
    target = Path(_safe_path(out))
    target.write_text(content, encoding="utf-8")
    return str(target)


def _is_binary_ext(name: str) -> bool:
    return os.path.splitext(name)[1].lower() in BINARY_EXT


def _read_text(path: str) -> Optional[str]:
    """读取一个已通过包含校验的文本文件；二进制/超大内容返回 None。"""
    try:
        if os.path.getsize(path) > 512 * 1024:
            return None
        with open(path, "rb") as f:
            head = f.read(1024)
        if b"\x00" in head:
            return None
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


def _iter_files(root: str):
    """遍历项目目录，跳过依赖/缓存/二进制；路径做包含校验防越界。"""
    root_real = os.path.realpath(root)
    if os.path.isfile(root_real):
        yield root_real
        return
    for dirpath, dirnames, filenames in os.walk(root_real):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith("egg-info")]
        for fn in filenames:
            path = os.path.realpath(os.path.join(dirpath, fn))
            if not (path == root_real or path.startswith(root_real + os.sep)):
                continue
            if _is_binary_ext(fn):
                continue
            yield path


def _rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, os.path.realpath(root))
    except ValueError:
        return path


def _line_findings(root: str, path: str, text: str, findings: list[dict]) -> None:
    rel = _rel(root, path)
    is_prompt_file = bool(PROMPT_MARK_RE.search(text)) and (
        "prompt" in rel.lower() or "system" in rel.lower() or "persona" in rel.lower())
    secret_in_prompt = False
    for i, line in enumerate(text.splitlines(), 1):
        for rule_id, severity, title, pattern in RULES:
            m = pattern.search(line)
            if not m:
                continue
            findings.append({"file": rel, "line": i, "severity": severity,
                             "rule": rule_id, "title": title,
                             "evidence": line.strip()[:160]})
            if severity == "high" and rule_id.startswith("SEC-"):
                secret_in_prompt = True
    if is_prompt_file and secret_in_prompt:
        findings.append({"file": rel, "line": 0, "severity": "high",
                         "rule": "PROMPT-SECRET",
                         "title": "提示词文件中包含疑似凭据（系统提示词可被逐字泄露）",
                         "evidence": "提示词文件命中凭据规则，详见同文件 SEC-* 条目"})


def _structured_checks(root: str, files: list[str], text_of: Callable[[str], Optional[str]],
                       findings: list[dict], notes: list[str]) -> None:
    for path in files:
        name = os.path.basename(path).lower()
        text = text_of(path)
        if text is None:
            continue
        # MCP 配置：复用 mcp-scan 静态审计
        if name.endswith(".json") and "mcpservers" in text.lower():
            try:
                servers = mcp_scan.load_servers(path)
            except Exception as e:
                notes.append(f"[{_rel(root, path)}] MCP 配置解析失败: {e}")
                servers = {}
            for sname, spec in servers.items():
                if isinstance(spec, dict):
                    for f in mcp_scan.audit_server(sname, spec):
                        findings.append({"file": _rel(root, path), "line": 0,
                                         "severity": f["severity"],
                                         "rule": "MCP-" + f["severity"].upper(),
                                         "title": f"MCP[{sname}] {f['title']}",
                                         "evidence": f["evidence"]})
        # .env 文件
        if name.startswith(".env") or name == "env":
            cred_lines = [i for i, ln in enumerate(text.splitlines(), 1)
                          if re.match(r"(?i)\s*[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=", ln)]
            if cred_lines:
                findings.append({"file": _rel(root, path), "line": cred_lines[0],
                                 "severity": "medium", "rule": "ENV-FILE",
                                 "title": f"环境变量文件包含疑似凭据（{len(cred_lines)} 处），且位于项目目录内",
                                 "evidence": text.splitlines()[cred_lines[0] - 1].strip()[:160]})
        # requirements.txt：未固定版本
        if name in ("requirements.txt", "requirements-dev.txt"):
            unpinned = [ln.strip() for ln in text.splitlines()
                        if ln.strip() and not ln.strip().startswith("#")
                        and not re.search(r"(==|>=|<=|~=|\s@)", ln)]
            risky = [ln for ln in unpinned
                     if ln.split("==")[0].split(">=")[0].strip().lower() in RISKY_PACKAGES]
            if unpinned:
                findings.append({"file": _rel(root, path), "line": 0, "severity": "low",
                                 "rule": "DEPS-UNPINNED",
                                 "title": f"{len(unpinned)} 个依赖未固定版本（供应链可替换）",
                                 "evidence": ", ".join(unpinned[:8])})
            for ln in risky:
                findings.append({"file": _rel(root, path), "line": 0, "severity": "medium",
                                 "rule": "DEPS-RISKY", "title": "依赖了需留意的包", "evidence": ln})


def run(root: str, max_bytes: int = 512 * 1024) -> tuple:
    """执行项目静态审计，返回 (findings, notes)。"""
    root = _safe_path(root)
    findings: list[dict] = []
    notes: list[str] = []
    files: list[str] = []
    texts: dict[str, Optional[str]] = {}
    skipped = 0
    for path in _iter_files(root):
        if os.path.getsize(path) > max_bytes:
            skipped += 1
            continue
        text = _read_text(path)
        if text is None:
            skipped += 1
            continue
        files.append(path)
        texts[path] = text
    notes.append(f"扫描文件 {len(files)} 个，跳过二进制/超大文件 {skipped} 个")
    for path in files:
        _line_findings(root, path, texts[path] or "", findings)
    _structured_checks(root, files, lambda p: texts.get(p), findings, notes)
    findings.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3),
                                 f["file"], f["line"]))
    return findings, notes


def counts(findings: list[dict]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")}


def print_findings(root: str, findings: list[dict], notes: list[str]) -> None:
    for n in notes:
        print("  - " + n)
    print()
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        print(f"  [{f['severity'].upper():<6}] {loc} {f['rule']} {f['title']}")
        print(f"           证据: {f['evidence']}")
    c = counts(findings)
    print()
    print(f"共 {len(findings)} 条发现: high {c['high']} / medium {c['medium']} / low {c['low']}（项目: {root}）")


def write_markdown(path: str, root: str, findings: list[dict], notes: list[str]) -> str:
    lines = ["# AgentScan 项目静态审计报告", "", f"- 项目: {root}", ""]
    c = counts(findings)
    lines.append(f"- 发现: **high {c['high']} / medium {c['medium']} / low {c['low']}**（共 {len(findings)} 条）")
    lines.append("")
    lines.append("> 说明：白盒规则审计，命中即列出真实代码行；medium/low 部分条目需人工确认是否构成实际风险。")
    lines.append("")
    if notes:
        lines.append("## 扫描说明")
        lines.append("")
        for n in notes:
            lines.append(f"- {n}")
        lines.append("")
    lines.append("## 发现明细")
    lines.append("")
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        lines.append(f"### [{f['severity'].upper()}] {f['rule']} {f['title']}")
        lines.append("")
        lines.append(f"- 位置: `{loc}`")
        lines.append(f"- 证据: `{f['evidence']}`")
        lines.append("")
    return _write_text(path, "\n".join(lines))


def write_json(path: str, root: str, findings: list[dict], notes: list[str]) -> str:
    doc = {"root": root, "summary": counts(findings), "total": len(findings),
           "findings": findings, "notes": notes}
    return _write_text(path, json.dumps(doc, ensure_ascii=False, indent=2))
