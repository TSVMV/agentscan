"""AgentScan 核心数据模型。

设计原则：
- 所有结论必须来自对真实目标的真实交互，不造任何模拟数据。
- 结论分五档：FAIL(确认漏洞) / SUSPECT(可疑待复核) / PASS(正常处置) / SKIP(目标不具备条件) / ERROR(执行异常)。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

SEVERITIES = ("high", "medium", "low")
SEV_WEIGHT = {"high": 3, "medium": 2, "low": 1}


class Status(str, Enum):
    FAIL = "FAIL"        # 确认存在漏洞：有真实响应/真实工具调用作为证据
    SUSPECT = "SUSPECT"  # 存在可疑迹象，但证据不足以确认，需人工复核
    PASS = "PASS"        # 测试已执行，目标正常处置
    SKIP = "SKIP"        # 目标不具备该测试所需的能力，附真实原因
    ERROR = "ERROR"      # 测试执行出错（网络、接口异常），附真实错误


@dataclass
class ToolCall:
    """目标 agent 真实发出的一次工具调用。"""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: Optional[str] = None

    def pretty(self) -> str:
        args = ", ".join(f"{k}={v!r}" for k, v in self.arguments.items())
        return f"{self.name}({args})" if args else f"{self.name}()"


@dataclass
class Tool:
    """扫描器托管沙箱工具定义（兼容 OpenAI function calling 格式）。"""

    name: str
    description: str
    parameters: dict[str, Any]

    def to_openai(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_dict(self) -> dict:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


@dataclass
class AgentResult:
    """目标 agent 的一次真实响应。"""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    http_status: Optional[int] = None
    raw: Optional[dict] = None


@dataclass
class Turn:
    """一轮真实对话记录。"""

    user: str
    assistant: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class Transcript:
    """一次测试的完整对话记录（全部为真实交互）。"""

    turns: list[Turn] = field(default_factory=list)

    def all_content(self) -> str:
        return "\n".join(t.assistant for t in self.turns if t.assistant)

    def all_tool_calls(self) -> list[ToolCall]:
        out: list[ToolCall] = []
        for t in self.turns:
            out.extend(t.tool_calls)
        return out

    def render(self) -> str:
        lines = []
        for i, t in enumerate(self.turns, 1):
            lines.append(f"[用户第{i}轮] {t.user}")
            if t.tool_calls:
                lines.append("[工具调用] " + " ; ".join(c.pretty() for c in t.tool_calls))
            if t.assistant:
                lines.append(f"[目标第{i}轮] {t.assistant}")
        return "\n".join(lines)


class Skipped(Exception):
    """该用例不适用于当前目标（附真实原因）。"""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class ScanContext:
    """一次扫描的上下文。"""

    canary: Optional[str] = None       # 仅当测试者拥有目标并自行埋入标记时使用
    payload_base: Optional[str] = None  # 本地 payload 服务的真实地址（间接注入用）
    judge: Optional[Callable[[str, str], dict]] = None  # 可选 LLM 评判 judge(question, transcript) -> dict
    sink: Optional[Any] = None         # 出口金丝雀收集器（egress 模块用）
    sink_token: Optional[str] = None   # 出口金丝雀的唯一标记
    egress_capable: bool = False       # 探针确认目标具备真实出站能力后置 True
    target_kind: str = "unknown"       # agent / bare-llm / unknown（能力探测结论）
    probe_note: str = ""               # 能力探测的真实过程记录
    host_tools: bool = False           # 是否启用扫描器托管沙箱工具
    sandbox_dir: Optional[str] = None  # 托管沙箱目录（真实文件）
    sandbox_exec: Optional[Callable[[str, dict[str, Any]], str]] = None  # 工具执行器
    allow_fetch_hosts: Optional[list[str]] = None  # fetch_url 额外允许的域名


@dataclass
class AttackCase:
    """一条攻击用例。"""

    case_id: str
    name: str
    category: str
    severity: str
    owasp: str
    description: str
    turns: list[str]                  # 依序发送的用户消息，支持 {payload_base}/{sink_base} 占位符
    detect: Callable[[Transcript, ScanContext], Optional[bool]]
    goal: str = ""                    # 攻击意图描述（供 LLM 评判使用）
    needs_tools: bool = False         # 该用例依赖工具能力（目标为裸模型时诚实跳过）


@dataclass
class CaseResult:
    """一条用例的真实判定结果。"""

    case: AttackCase
    status: Status
    reason: str
    transcript: Transcript = field(default_factory=Transcript)
    http_status: Optional[int] = None
    evidence: str = ""

    @property
    def case_id(self) -> str:
        return self.case.case_id

    @property
    def name(self) -> str:
        return self.case.name

    @property
    def category(self) -> str:
        return self.case.category

    @property
    def severity(self) -> str:
        return self.case.severity

    @property
    def owasp(self) -> str:
        return self.case.owasp
