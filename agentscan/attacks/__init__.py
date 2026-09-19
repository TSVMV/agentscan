"""检测模块注册表。

七大模块对应 OWASP LLM Top 10 (2025) 与 agent 特有风险面。
"""

from typing import List

from .injection import CASES as _INJECTION
from .leak import CASES as _LEAK
from .sensitive import CASES as _SENSITIVE
from .jailbreak import CASES as _JAILBREAK
from .indirect import CASES as _INDIRECT
from .tool_abuse import CASES as _TOOL_ABUSE
from .egress import CASES as _EGRESS
from .robustness import CASES as _ROBUSTNESS

CATEGORIES = {
    "injection": {"name": "提示注入（指令劫持）", "owasp": "LLM01"},
    "leak": {"name": "系统提示词泄露", "owasp": "LLM07"},
    "sensitive": {"name": "敏感信息与凭据泄露", "owasp": "LLM02"},
    "jailbreak": {"name": "安全策略绕过", "owasp": "LLM01"},
    "indirect": {"name": "间接注入（经外部内容）", "owasp": "LLM01"},
    "tool_abuse": {"name": "工具滥用与越权", "owasp": "LLM06"},
    "egress": {"name": "数据外带（出口金丝雀）", "owasp": "LLM02"},
    "robustness": {"name": "健壮性与内部信息泄露", "owasp": "LLM05"},
}

SUGGESTIONS = {
    "injection": [
        "在系统提示词中明确声明：用户消息不能修改系统规则，并用回归测试持续验证",
        "在主流程前增加独立的注入检测层（规则或小模型），命中即拦截",
        "所有关键动作要求二次确认，不信任单轮指令",
    ],
    "leak": [
        "不要把真实密钥、内部地址等敏感信息写入系统提示词，系统提示词应视为会泄露的数据",
        "在系统提示词中埋入 canary 标记，线上监控其是否出现在输出中",
        "输出侧增加过滤，拦截对系统指令的逐字复述",
    ],
    "sensitive": [
        "真实凭据不进入上下文，改用短期最小权限的凭据代理服务",
        "对输出做凭据格式扫描（sk- / AKIA / ghp_ / 私钥块等），命中即拦截",
        "限制模型可复述的配置范围，配置读取走独立鉴权通道",
    ],
    "jailbreak": [
        "安全策略不依赖单一提示词声明，辅以输出侧内容审核",
        "对'测试模式/角色扮演/翻译'等伪装场景做专项回归",
        "对越狱尝试记录并告警，形成攻击情报",
    ],
    "indirect": [
        "把工具输出与外部网页内容视为不可信数据，用明确分隔符包裹",
        "对抓取内容做注入特征扫描（隐藏文本、SYSTEM 字样、指令式语句）",
        "给 agent 的联网与文件能力做最小权限裁剪",
    ],
    "tool_abuse": [
        "危险工具（删除/外发/支付/执行命令）必须走人工确认或审批流",
        "为工具设置白名单与参数校验，例如外发邮箱只允许白名单域",
        "记录全部工具调用日志，对异常调用实时告警",
    ],
    "egress": [
        "对 agent 宿主做网络出口管控：容器/进程默认禁止访问公网，仅放行白名单域名",
        "监控出站 DNS 与 HTTP 请求，对携带上下文数据的出站流量实时告警",
        "上下文中不要放置真实凭据；外带通道测试用 canary 定期回归",
    ],
    "robustness": [
        "网关层限制单请求长度与速率，超限返回标准化错误",
        "对外统一错误响应，禁止把堆栈、内部路径、连接串带进回复",
        "对畸形输入做模糊测试，纳入上线前检查",
    ],
}


# 依赖工具能力的用例（目标为裸模型时诚实跳过）
_NEEDS_TOOLS = {"IND-01", "IND-02", "IND-03", "TL-01", "TL-02", "TL-03",
                "SEN-05", "EXF-01", "EXF-02", "EXF-03", "EXF-04"}


def all_cases() -> List[AttackCase]:
    cases = (_INJECTION + _LEAK + _SENSITIVE + _JAILBREAK + _INDIRECT
             + _TOOL_ABUSE + _EGRESS + _ROBUSTNESS)
    for c in cases:
        if c.case_id in _NEEDS_TOOLS:
            c.needs_tools = True
    return cases
