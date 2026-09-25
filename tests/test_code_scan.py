"""code-scan 静态审计专项测试。

直接运行: python tests/test_code_scan.py
覆盖：凭据/提示词卫生/.env/依赖/MCP 静态审计的结构化检查，以及规则正则本身。
规则命中向量存于 tests/fixtures/rule_vectors.json（数据与代码分离）。
"""

import json
import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
sys.path.insert(0, _PROJECT_ROOT)

from agentscan import code_scan  # noqa: E402

failures = []
FIXTURE = os.path.join(_TESTS_DIR, "fixtures", "sample_agent_project")
VECTORS = os.path.join(_TESTS_DIR, "fixtures", "rule_vectors.json")


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if not cond and detail else ""))
    if not cond:
        failures.append(name)


def rule_by_id(rule_id: str):
    return {r[0]: r[3] for r in code_scan.RULES}[rule_id]


def test_project_scan() -> None:
    print("[project scan on fixture]")
    findings, notes = code_scan.run(FIXTURE)
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f["rule"], []).append(f)

    check("提示词文件检出硬编码 sk- 密钥（SEC-SK）", "SEC-SK" in by_rule, str(list(by_rule)))
    check("提示词文件检出 key=value 凭据（SEC-KEYVAL/UNQ）",
          "SEC-KEYVAL" in by_rule or "SEC-KEYVAL-UNQ" in by_rule)
    check("提示词卫生专项发现（PROMPT-SECRET）", "PROMPT-SECRET" in by_rule)
    check("提示词文件检出明文 http 内部地址（NET-HTTP）", "NET-HTTP" in by_rule)
    check(".env 凭据检出（ENV-FILE）", "ENV-FILE" in by_rule)
    check("依赖未固定版本检出（DEPS-UNPINNED）", "DEPS-UNPINNED" in by_rule)
    check("风险依赖检出（DEPS-RISKY: pyyaml）", "DEPS-RISKY" in by_rule)
    check("MCP 静态审计复用（curl|sh -> high）",
          any(f["severity"] == "high" and "evil-fetcher" in f["title"] for f in findings),
          str([f["title"] for f in findings if "MCP" in f["rule"]]))
    check("AWS 凭据检出（SEC-AWS，来自 .env）", "SEC-AWS" in by_rule)
    check("对照文件零发现",
          not any(f["file"].startswith("clean.py") for f in findings),
          str([f["file"] for f in findings if f["file"].startswith("clean")]))
    c = code_scan.counts(findings)
    check("存在高危发现（退出码 1 语义）", c["high"] >= 3, str(c))


def test_rule_patterns() -> None:
    print("[rule regex engine]")
    with open(VECTORS, encoding="utf-8") as f:
        vectors = json.load(f)
    for rule_id, sample in vectors.items():
        pattern = rule_by_id(rule_id)
        check(f"规则 {rule_id} 命中测试向量", bool(pattern.search(sample)), sample)
    # 对照：正常代码不应命中
    normal = "result = safe_call(payload)"
    check("规则 EXEC-EVAL 不误报正常调用", not rule_by_id("EXEC-EVAL").search(normal))


if __name__ == "__main__":
    test_project_scan()
    test_rule_patterns()
    print()
    if failures:
        print(f"[FAIL] {len(failures)} 项未通过: {', '.join(failures)}")
        raise SystemExit(1)
    print("[PASS] code-scan 测试全部通过")
