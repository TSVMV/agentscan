"""MCP (Model Context Protocol) 安全扫描。

两层检测，全部基于真实数据：
1. 静态审计：解析 MCP 配置文件（mcpServers 格式），审计启动命令/参数/环境变量中的危险模式
2. 动态扫描：以 MCP 客户端身份真实连接 server（stdio / streamable HTTP），枚举 tools，
   检测工具描述投毒、已知外发端点、名称仿冒/遮蔽

用法:
  agentscan mcp-scan --config claude_desktop_config.json --connect
  agentscan mcp-scan --url http://127.0.0.1:3000/mcp
"""

import contextlib
import difflib
import json
import os
import queue
import re
import subprocess
import threading
import time
from typing import Optional

import requests

CLIENT_INFO = {"name": "agentscan", "version": "0.3.0"}
PROTOCOL_VERSION = "2024-11-05"

# ---------------- 规则 ----------------

EXFIL_ENDPOINTS_RE = re.compile(
    r"(webhook\.site|requestbin[\w.\-]*|pipedream\.net|ngrok(?:\.io|\.com|\.free|-app\.com)|"
    r"pastebin\.com|transfer\.sh|burpcollaborator\.net|interact\.sh|dnslog[\w.\-]*)",
    re.I,
)
DOWNLOADER_RE = re.compile(r"\b(curl|wget|invoke-webrequest|\biwr\b|certutil)\b", re.I)
SHELL_RE = re.compile(r"(\|\s*(ba)?sh\b|\|\s*bash\b|/bin/(ba)?sh\b|\bpowershell\b|\bpwsh\b|cmd(?:\.exe)?\s*/c)", re.I)
DYNEXEC_RE = re.compile(r"(\beval\b|invoke-expression|\biex\b|\bexec\(|-enc\b|base64\s+(-d|-D|/d)\b)", re.I)
INTERP_INLINE_RE = re.compile(r"(python[\d.]*\s+(-c|--command)\b|node\s+(-e|--eval)\b|ruby\s+-e\b|perl\s+-e\b)", re.I)
ONESHOT_PKG_RE = re.compile(r"\b(npx|uvx|bunx)\b", re.I)
ONESHOT_YES_RE = re.compile(r"(-y\b|--yes\b)", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
SENSITIVE_ENV_RE = re.compile(r"(api[_-]?key|token|secret|password|credential)", re.I)
DESC_INJECTION_RE = re.compile(
    r"((?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)"
    r"|system\s+(?:prompt|message)"
    r"|<\s*(?:system|important)\s*>"
    r"|(?:you|assistant|model)\s+(?:must|should)\s+(?:always|now)"
    r"|do not (?:tell|inform|reveal|mention)"
    r"|secretly|before (?:answering|responding|doing anything)"
    r"|忽略(?:之前|以上|前面|系统)|系统提示|不要(?:告诉|透露|提及)"
    r"|当用户|调用其他工具时|必须先)",
    re.I,
)
COMMON_TOOL_NAMES = ["filesystem", "fetch", "git", "github", "sqlite", "postgres",
                     "puppeteer", "slack", "memory", "search", "browser", "shell"]


def _finding(server: str, tool: str, severity: str, title: str, evidence: str) -> dict:
    return {"server": server, "tool": tool, "severity": severity,
            "title": title, "evidence": evidence[:200]}


# ---------------- 静态审计 ----------------

def load_servers(config_path: str) -> dict[str, dict]:
    """从配置文件读取 MCP server 定义，兼容 mcpServers / servers 键与顶层字典。"""
    with open(config_path, encoding="utf-8") as f:
        cfg = json.load(f)
    if isinstance(cfg, dict):
        for key in ("mcpServers", "mcp_servers", "servers"):
            if isinstance(cfg.get(key), dict):
                return cfg[key]
        if cfg and all(isinstance(v, dict) for v in cfg.values()):
            return cfg
    return {}


def audit_server(name: str, spec: dict) -> list[dict]:
    findings: list[dict] = []
    cmd = str(spec.get("command") or "")
    args = " ".join(str(a) for a in spec.get("args", []))
    env = spec.get("env") or {}
    env_vals = " ".join(str(v) for v in env.values())
    blob = " ".join([cmd, args, env_vals])

    def add(sev: str, title: str, m) -> None:
        if m:
            findings.append(_finding(name, "-", sev, title, m.group(0)))

    add("high", "启动命令包含下载器（存在远程拉取执行的风险面）", DOWNLOADER_RE.search(blob))
    add("high", "命令经 shell 解释执行，存在命令注入面", SHELL_RE.search(blob))
    add("high", "包含动态代码执行（eval/exec/-enc/base64 解码）", DYNEXEC_RE.search(blob))
    add("high", "解释器内联代码执行（python -c / node -e 等）", INTERP_INLINE_RE.search(blob))
    add("high", "包含已知外发/收集端点", EXFIL_ENDPOINTS_RE.search(blob))
    if ONESHOT_PKG_RE.search(blob) and ONESHOT_YES_RE.search(blob):
        add("medium", "一次性拉起第三方包且未固定版本，存在供应链替换风险",
            ONESHOT_PKG_RE.search(blob))
    m = URL_RE.search(" ".join([cmd, args]))
    if m:
        add("medium", "启动命令/参数包含远程 URL（内容可被远端替换）", m)
    for k in env:
        if SENSITIVE_ENV_RE.search(str(k)):
            findings.append(_finding(name, "-", "low",
                                     "向该 server 传递敏感环境变量（server 可读取）", str(k)))
    return findings


# ---------------- 动态客户端 ----------------

def _recv_until(q: "queue.Queue[str]", deadline: float, want_id: Optional[int]) -> Optional[dict]:
    while time.time() < deadline:
        try:
            line = q.get(timeout=max(0.1, deadline - time.time()))
        except queue.Empty:
            return None
        if line is None:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue  # 很多 server 会先打印日志行，跳过非 JSON 行
        if want_id is None or obj.get("id") == want_id:
            return obj
    return None


def stdio_tools_list(command: str, args: list[str], env: Optional[dict] = None,
                     timeout: float = 20.0) -> tuple[Optional[list[dict]], Optional[str]]:
    """以 MCP 客户端身份通过 stdio 真实连接 server，返回 (tools, error)。"""
    full_env = {**os.environ, **(env or {})}
    try:
        proc = subprocess.Popen([command] + list(args), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace", env=full_env)
    except Exception as e:
        return None, f"启动失败: {e}"
    q: queue.Queue[str] = queue.Queue()

    def reader() -> None:
        try:
            for line in proc.stdout:
                q.put(line)
        except Exception:
            pass
        q.put(None)

    threading.Thread(target=reader, daemon=True).start()

    def send(obj: dict) -> None:
        try:
            proc.stdin.write(json.dumps(obj) + "\n")
            proc.stdin.flush()
        except Exception:
            pass

    deadline = time.time() + timeout
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO}})
    init = _recv_until(q, deadline, 1)
    if init is None:
        proc.kill()
        return None, "initialize 无响应（超时）"
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    resp = _recv_until(q, deadline, 2)
    tools, err = None, None
    if resp is None:
        err = "tools/list 无响应（超时）"
    elif "error" in resp:
        err = f"tools/list 错误: {resp['error']}"
    else:
        tools = (resp.get("result") or {}).get("tools") or []
    with contextlib.suppress(Exception):
        proc.stdin.close()
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        with contextlib.suppress(Exception):
            proc.kill()
    return tools, err


def _parse_body(r: requests.Response) -> Optional[dict]:
    ct = r.headers.get("Content-Type", "")
    if "text/event-stream" in ct:
        for line in r.text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except Exception:
                    continue
        return None
    try:
        return json.loads(r.text)
    except Exception:
        return None


def http_tools_list(url: str, timeout: float = 20.0) -> tuple[Optional[list[dict]], Optional[str]]:
    """以 MCP 客户端身份通过 streamable HTTP 真实连接 server，返回 (tools, error)。"""
    with requests.Session() as session:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

        def post(payload: dict) -> requests.Response:
            return session.post(url, json=payload, headers=headers, timeout=timeout)

        try:
            r = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO}})
        except Exception as e:
            return None, f"连接失败: {e}"
        if r.status_code >= 400:
            return None, f"initialize HTTP {r.status_code}"
        obj = _parse_body(r)
        if obj is None or "result" not in obj:
            return None, "initialize 响应无法解析"
        sid = r.headers.get("mcp-session-id")
        if sid:
            headers["mcp-session-id"] = sid
        with contextlib.suppress(Exception):
            post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        try:
            r2 = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        except Exception as e:
            return None, f"tools/list 请求失败: {e}"
        if r2.status_code >= 400:
            return None, f"tools/list HTTP {r2.status_code}"
        obj2 = _parse_body(r2)
        if obj2 is None:
            return None, "tools/list 响应无法解析"
        if "error" in obj2:
            return None, f"tools/list 错误: {obj2['error']}"
        return (obj2.get("result") or {}).get("tools") or [], None


def analyze_tools(server: str, tools: list[dict]) -> list[dict]:
    """对真实枚举到的工具做描述投毒 / 外发端点 / 名称仿冒检测。"""
    findings: list[dict] = []
    for t in tools:
        name = str(t.get("name", ""))
        desc = str(t.get("description", ""))

        m = DESC_INJECTION_RE.search(desc)
        if m:
            findings.append(_finding(server, name, "high",
                                     "工具描述疑似注入指令（描述投毒）", m.group(0)))
        m = EXFIL_ENDPOINTS_RE.search(desc)
        if m:
            findings.append(_finding(server, name, "high",
                                     "工具描述包含已知外发/收集端点", m.group(0)))
        m = URL_RE.search(desc)
        if m:
            findings.append(_finding(server, name, "low",
                                     "工具描述包含 URL", m.group(0)))
        low = name.lower()
        if low:
            for base in COMMON_TOOL_NAMES:
                if low == base:
                    break
                ratio = difflib.SequenceMatcher(None, low, base).ratio()
                if ratio >= 0.85:
                    findings.append(_finding(server, name, "medium",
                                             f"工具名与常见官方工具 {base} 高度相似（{ratio:.2f}），存在仿冒/遮蔽可能",
                                             name))
                    break
    return findings


# ---------------- 入口 ----------------

def _safe_path(p: str) -> str:
    """规范化用户提供的文件路径：展开用户目录、折叠相对段，禁止残留父目录穿越段。"""
    norm = os.path.abspath(os.path.expanduser(p))
    if os.pardir in norm.split(os.sep) or norm.strip() in ("", os.sep):
        raise SystemExit(f"非法路径: {p}")
    return norm


def dump_json(findings: list[dict], notes: list[str], path: str) -> str:
    """把扫描发现写入 JSON 文件（路径规范化校验后），返回实际路径。"""
    out = _safe_path(path)
    with open(out, "w", encoding="utf-8") as fp:
        json.dump({"findings": findings, "notes": notes}, fp, ensure_ascii=False, indent=2)
    return out


def run(config: Optional[str] = None, url: Optional[str] = None,
        connect: bool = False, timeout: float = 20.0,
        force_connect: bool = False) -> tuple[list[dict], list[str]]:
    """执行扫描，返回 (findings, notes)。

    安全门：静态审计发现高危问题的 stdio server 默认不会被启动（避免执行不可信命令），
    确有必要时以 force_connect 显式放行。
    """
    if config:
        config = _safe_path(config)
    findings: list[dict] = []
    notes: list[str] = []
    tool_owner: dict[str, list[str]] = {}  # 工具名 -> 提供它的 server 列表（遮蔽检测）
    if config:
        servers = load_servers(config)
        if not servers:
            notes.append(f"配置 {config} 中未找到 MCP server 定义")
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            server_findings = audit_server(name, spec)
            findings.extend(server_findings)
            if not connect:
                continue
            has_high = any(f["severity"] == "high" for f in server_findings)
            if spec.get("command") and has_high and not force_connect:
                notes.append(f"[{name}] 已跳过动态连接：静态审计发现高危问题，默认不执行不可信命令"
                             f"（确需连接请加 --force-connect）")
                continue
            if spec.get("command"):
                tools, err = stdio_tools_list(spec["command"], spec.get("args", []),
                                              spec.get("env"), timeout)
            elif spec.get("url"):
                tools, err = http_tools_list(spec["url"], timeout)
            else:
                tools, err = None, "spec 无 command/url，无法动态连接"
            if err:
                notes.append(f"[{name}] 动态连接失败: {err}")
            else:
                notes.append(f"[{name}] 动态枚举到 {len(tools or [])} 个工具")
                findings.extend(analyze_tools(name, tools or []))
                for t in tools or []:
                    tool_owner.setdefault(str(t.get("name", "")), []).append(name)
    if url:
        findings.extend(audit_server("<命令行URL>", {"url": url}))
        tools, err = http_tools_list(url, timeout)
        if err:
            notes.append(f"[{url}] 动态连接失败: {err}")
        else:
            notes.append(f"[{url}] 动态枚举到 {len(tools or [])} 个工具")
            findings.extend(analyze_tools(url, tools or []))
            for t in tools or []:
                tool_owner.setdefault(str(t.get("name", "")), []).append("<命令行URL>")
    # 跨 server 同名工具：后注册者可能遮蔽先注册者（MCP 遮蔽攻击面）
    for tool_name, owners in tool_owner.items():
        if len(owners) > 1:
            findings.append(_finding("+".join(owners), tool_name, "medium",
                                     "多个 server 提供同名工具，存在遮蔽/覆盖风险", tool_name))
    return findings, notes
