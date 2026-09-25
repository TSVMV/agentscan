"""AgentScan 命令行入口。

子命令:
  list   列出全部检测模块与用例
  probe  对目标地址做真实探测（识别接口方言、枚举模型）
  scan   对目标执行安全扫描
"""

import argparse
import importlib.util
import json
import os
import sys
import time
from typing import Callable, Optional

from . import __version__, code_scan, docker_runner, mcp_scan, payload_server, report
from .adapter import (
    GenericHTTPAdapter,
    PythonAdapter,
    build_adapter,
    discover,
)
from .attacks import CATEGORIES, all_cases
from .core import ScanContext
from .detectors import llm_judge_fn
from .egress_sink import start_sink, stop_sink
from .scanner import probe_capability, scan

BANNER = r"""
    _                    _        _____
   / \   __ _  ___ _ __ | |_ ___ |  ___|__  _ __ ___  ___
  / _ \ / _` |/ _ \ '_ \| __/ _ \| |_ / _ \| '__/ _ \/ __|
 / ___ \ (_| |  __/ | | | || (_) |  _| (_) | | |  __/\__ \
/_/   \_\__, |\___|_| |_|\__\___/|_|  \___/|_|  \___||___/
        |___/   AI Agent Security Scanner v""" + __version__ + """

仅用于测试你拥有或已获授权的 agent。所有结论基于真实交互。
"""


def load_python_adapter(path: str) -> PythonAdapter:
    spec = importlib.util.spec_from_file_location("agentscan_user_adapter", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"无法加载 adapter 文件: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "run"):
        raise SystemExit("adapter 文件必须定义 run(messages, tools=None) 函数")
    return PythonAdapter(mod.run, label=path)


def cmd_list(args) -> int:
    print(f"AgentScan v{__version__} 检测用例清单（共 {len(all_cases())} 条）")
    print()
    cases = all_cases()
    for cat, meta in CATEGORIES.items():
        print(f"[{cat}] {meta['name']}  (OWASP {meta['owasp']})")
        for c in [x for x in cases if x.category == cat]:
            print(f"    {c.case_id:<8} {c.severity.upper():<6} {c.name}")
        print()
    return 0


def cmd_probe(args) -> int:
    print(f"探测目标: {args.url}")
    info = discover(args.url, api_key=args.api_key)
    for note in info["notes"]:
        print(f"  - {note}")
    print()
    if not info["alive"]:
        print("结论: 目标无 HTTP 响应（未启动或地址错误）")
        return 2
    if info["openai_base"]:
        print(f"结论: OpenAI 兼容接口, base = {info['openai_base']}")
    if info["ollama"]:
        print("结论: Ollama 原生接口（--api ollama）")
    if info["models"]:
        print(f"模型列表: {', '.join(info['models'][:20])}")
    elif info["alive"]:
        print("未探测到模型列表接口，scan 时请用 --model 显式指定。")
    return 0


def _resolve_target(args):
    """根据参数构造真实目标的 adapter。返回 (adapter, cleanup, target_prefix)。"""
    cleanup: Optional[Callable[[], None]] = None
    if args.docker_image:
        if not args.docker_port:
            raise SystemExit("使用 --docker-image 时必须同时提供 --docker-port（容器内服务端口）")
        print(f"启动 docker 目标: {args.docker_image} (容器端口 {args.docker_port})")
        info = docker_runner.start(args.docker_image, args.docker_port,
                                   extra_args=args.docker_arg, wait_timeout=args.docker_wait)
        print(f"容器已就绪: {info['url']} (container {info['container_id'][:12]})")
        if args.keep_container:
            cleanup = None
            print("按 --keep-container 要求保留容器，请自行清理: docker rm -f " + info["container_id"][:12])
        else:
            cid = info["container_id"]
            cleanup = lambda: docker_runner.stop(cid)  # noqa: E731
        adapter = build_adapter(info["url"], args.model, args.api_key, args.api, args.timeout)
        return adapter, cleanup

    if args.config:
        with open(args.config, encoding="utf-8") as f:
            cfg = json.load(f)
        return GenericHTTPAdapter(cfg, timeout=args.timeout), cleanup

    if args.adapter:
        return load_python_adapter(args.adapter), cleanup

    if args.url:
        return build_adapter(args.url, args.model, args.api_key, args.api, args.timeout), cleanup

    raise SystemExit("必须指定目标之一: --url / --docker-image / --config / --adapter（先可用 agentscan probe 试探）")


def cmd_scan(args) -> int:
    print(BANNER)
    t0 = time.time()
    adapter, cleanup = _resolve_target(args)
    target = f"{adapter.name}" + (f":{args.model}" if getattr(adapter, "model", None) and adapter.name != "generic-http" else "")

    ctx = ScanContext(canary=args.canary)
    if args.judge_url:
        if not args.judge_model:
            raise SystemExit("使用 --judge-url 时必须提供 --judge-model")
        ctx.judge = llm_judge_fn(args.judge_url, args.judge_model, api_key=args.judge_api_key, timeout=args.timeout)
        print(f"已启用独立 LLM 评判: {args.judge_model}")

    only = [m.strip() for m in args.module.split(",") if m.strip()] if args.module else None
    if only:
        print(f"模块过滤: {', '.join(only)}")

    if args.no_tools:
        ctx.target_kind = "bare-llm"
        ctx.probe_note = "--no-tools 指定：跳过能力探测，工具能力类用例将诚实跳过"
        print("目标分类: 已按 --no-tools 禁用工具托管")
    else:
        probe_capability(adapter, ctx)
        kind_label = {"agent": "AGENT（function calling 可用，已托管沙箱工具）",
                      "bare-llm": "AI（裸模型）", "unknown": "未知（探测未完成）"}.get(ctx.target_kind, ctx.target_kind)
        print(f"目标分类: {kind_label}")
        print(f"探测详情: {ctx.probe_note}")

    server = None
    sink = None
    try:
        if not only or "indirect" in only:
            server, base = payload_server.start()
            ctx.payload_base = base
            print(f"间接注入 payload 服务已启动: {base} (仅本机可访问)")
        if not only or "egress" in only:
            sink, http_port, dns_port = start_sink()
            ctx.sink = sink
            ctx.sink_token = args.canary or ("AS" + os.urandom(4).hex().upper())
            sink.http_base = f"http://{args.sink_host}:{http_port}"
            print(f"出口金丝雀已启动: HTTP {sink.http_base} / DNS :{dns_port} (token {ctx.sink_token})")
        print(f"开始扫描 {target} ...\n")
        results = scan(adapter, ctx, only=only, severity_min=args.severity,
                       delay=args.delay, on_done=report.print_progress)
    finally:
        payload_server.stop(server)
        stop_sink(sink)
        if cleanup:
            cleanup()

    elapsed = time.time() - t0
    agg = report.print_summary(results, target, elapsed)

    meta = {"version": __version__, "canary": bool(args.canary),
            "judge": bool(args.judge_url), "modules": only or list(CATEGORIES),
            "target_kind": ctx.target_kind, "probe": ctx.probe_note}
    if args.output:
        report.write_markdown(args.output, target, results, meta)
        print(f"Markdown 报告已写入: {args.output}")
    if args.json:
        report.write_json(args.json, target, results, meta)
        print(f"JSON 报告已写入: {args.json}")

    if agg["counts"]["FAIL"] > 0:
        return 1
    if agg["counts"]["ERROR"] > 0 and agg["counts"]["PASS"] == 0 and agg["counts"]["SUSPECT"] == 0:
        return 2
    return 0


def cmd_mcp_scan(args) -> int:
    print(BANNER)
    if not args.config and not args.url:
        raise SystemExit("必须提供 --config 或 --url 之一")
    findings, notes = [], []
    for cfg in args.config or []:
        try:
            servers = mcp_scan.load_servers(cfg)
        except SystemExit:
            raise
        except Exception as e:
            print(f"配置 {cfg} 读取失败: {e}")
            continue
        print(f"配置 {cfg}: {len(servers)} 个 server")
        f, n = mcp_scan.run(config=cfg, connect=args.connect, timeout=args.timeout,
                            force_connect=args.force_connect)
        findings.extend(f)
        notes.extend(n)
    for u in args.url or []:
        f, n = mcp_scan.run(url=u, connect=True, timeout=args.timeout)
        findings.extend(f)
        notes.extend(n)
    for n in notes:
        print("  - " + n)
    print()
    for f in findings:
        print(f"  [{f['severity'].upper():<6}] {f['server']}/{f['tool']}: {f['title']}")
        print(f"           证据: {f['evidence']}")
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in ("high", "medium", "low")}
    print()
    print(f"共 {len(findings)} 条发现: high {counts['high']} / medium {counts['medium']} / low {counts['low']}")
    if args.json:
        out = mcp_scan.dump_json(findings, notes, args.json)
        print(f"JSON 报告已写入: {out}")
    return 1 if counts["high"] else 0


def cmd_code_scan(args) -> int:
    print(BANNER)
    root = code_scan._safe_path(args.path)
    print(f"静态审计目标: {root}")
    findings, notes = code_scan.run(root, max_bytes=args.max_size * 1024)
    code_scan.print_findings(root, findings, notes)
    if args.output:
        out = code_scan.write_markdown(args.output, root, findings, notes)
        print(f"Markdown 报告已写入: {out}")
    if args.json:
        out = code_scan.write_json(args.json, root, findings, notes)
        print(f"JSON 报告已写入: {out}")
    return 1 if code_scan.counts(findings)["high"] else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentscan",
        description="AgentScan —— AI Agent 安全检测工具（多维度、真实数据、支持本地与 docker 目标）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  agentscan probe --url http://127.0.0.1:11434\n"
            "  agentscan scan --url http://127.0.0.1:11434 --api ollama\n"
            "  agentscan scan --url https://api.openai.com/v1 --model gpt-4o-mini --api-key sk-xxx\n"
            "  agentscan scan --docker-image my-agent:latest --docker-port 8000\n"
            "  agentscan scan --config target.json --output report.md --json report.json\n"
            "  agentscan scan --url http://127.0.0.1:8000/v1 --module injection,leak --severity high\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"agentscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="列出全部检测模块与用例")
    p_list.set_defaults(func=cmd_list)

    p_probe = sub.add_parser("probe", help="探测目标接口方言与模型列表")
    p_probe.add_argument("--url", required=True, help="目标地址，如 http://127.0.0.1:8000")
    p_probe.add_argument("--api-key", default=None, help="Bearer token（可选）")
    p_probe.set_defaults(func=cmd_probe)

    p_scan = sub.add_parser("scan", help="对目标执行安全扫描")
    tgt = p_scan.add_argument_group("目标（四选一）")
    tgt.add_argument("--url", default=None, help="OpenAI 兼容或 Ollama 服务地址")
    tgt.add_argument("--docker-image", default=None, help="用 docker 启动目标镜像并扫描")
    tgt.add_argument("--config", default=None, help="通用 HTTP 模板配置文件 (JSON)")
    tgt.add_argument("--adapter", default=None, help="进程内 Python adapter 文件（定义 run 函数）")
    common = p_scan.add_argument_group("目标参数")
    common.add_argument("--model", default=None, help="模型名（未指定时尝试从目标自动发现）")
    common.add_argument("--api-key", default=None, help="Bearer token（可选）")
    common.add_argument("--api", default="auto", choices=["auto", "openai", "ollama"], help="接口方言（默认自动识别）")
    common.add_argument("--timeout", type=int, default=120, help="单次请求超时秒数")
    common.add_argument("--docker-port", type=int, default=None, help="docker 目标在容器内监听的端口")
    common.add_argument("--docker-arg", action="append", default=None,
                        help="额外的 docker run 参数，如 -e API_KEY=xxx（可多次）")
    common.add_argument("--docker-wait", type=int, default=240, help="等待 docker 目标就绪的秒数")
    common.add_argument("--keep-container", action="store_true", help="扫描后保留 docker 容器（调试用）")
    common.add_argument("--sink-host", default="127.0.0.1",
                        help="出口金丝雀对目标暴露的主机地址（docker 目标用 host.docker.internal）")
    scanopt = p_scan.add_argument_group("扫描选项")
    scanopt.add_argument("--module", default=None, help=f"只跑指定模块，逗号分隔: {','.join(CATEGORIES)}")
    scanopt.add_argument("--severity", default=None, choices=["high", "medium", "low"], help="只跑不低于该严重度的用例")
    scanopt.add_argument("--no-tools", action="store_true",
                         help="禁用工具能力探测与沙箱工具托管（按裸模型扫描）")
    scanopt.add_argument("--canary", default=None, help="canary 蜜罐标记（须已埋入目标系统提示词）")
    scanopt.add_argument("--judge-url", default=None, help="独立 LLM 评判的 OpenAI 兼容地址（可选）")
    scanopt.add_argument("--judge-model", default=None, help="评判模型名")
    scanopt.add_argument("--judge-api-key", default=None, help="评判模型 API key（可选）")
    scanopt.add_argument("--delay", type=float, default=0.0, help="每条用例之间的间隔秒数")
    scanopt.add_argument("--output", default=None, help="Markdown 报告输出路径")
    scanopt.add_argument("--json", default=None, help="JSON 报告输出路径")
    p_scan.set_defaults(func=cmd_scan)

    p_mcp = sub.add_parser("mcp-scan", help="扫描 MCP 配置与 MCP server（静态审计 + 动态工具投毒检测）")
    p_mcp.add_argument("--config", action="append", default=None,
                       help="MCP 配置文件路径（mcpServers 格式，可多次）")
    p_mcp.add_argument("--url", action="append", default=None,
                       help="远程 MCP server 的 streamable HTTP 地址（可多次）")
    p_mcp.add_argument("--connect", action="store_true",
                       help="动态连接 server 并枚举工具做投毒检测")
    p_mcp.add_argument("--force-connect", action="store_true",
                       help="允许动态连接静态审计高危的 server（会真实执行其启动命令，慎用）")
    p_mcp.add_argument("--json", default=None, help="JSON 输出路径")
    p_mcp.add_argument("--timeout", type=float, default=20.0, help="动态连接超时秒数")
    p_mcp.set_defaults(func=cmd_mcp_scan)

    p_code = sub.add_parser("code-scan", help="对一个 AGENT 项目的文件做静态安全审计（白盒，无需运行目标）")
    p_code.add_argument("--path", required=True, help="项目目录或单个文件")
    p_code.add_argument("--max-size", type=int, default=512, help="单文件大小上限 KB（默认 512）")
    p_code.add_argument("--output", default=None, help="Markdown 报告输出路径")
    p_code.add_argument("--json", default=None, help="JSON 报告输出路径")
    p_code.set_defaults(func=cmd_code_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已中断。")
        sys.exit(130)
