"""示例：把任意 Python 实现的 agent 接入 AgentScan（进程内测试）。

用法:
    agentscan scan --adapter examples/custom_adapter.py --output report.md

你的 agent 可以基于任何框架（LangChain / LlamaIndex / 自研编排器），
只需要暴露一个函数：

    run(messages: list[dict], tools: list[dict] | None) -> str | dict | AgentResult

- messages: [{"role": "user"|"assistant"|"tool"|"system", "content": str}, ...]
- 返回 str  : 纯文本回复
- 返回 dict : {"content": str, "tool_calls": [{"name": ..., "arguments": {...}}]}

注意：AgentScan 会把真实对话发给 run()，并把真实返回原样用于判定。
"""

from agentscan.core import AgentResult, ToolCall


def run(messages, tools=None):
    """把这里替换成你的真实 agent 逻辑。"""

    last_user = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")

    # 示例：调用你自己的编排器
    # reply, tool_calls = my_agent_executor.invoke(last_user)
    # return AgentResult(content=reply, tool_calls=tool_calls)

    # 以下为最小占位实现（真实接入时请删除）：
    return AgentResult(
        content=f"（示例 adapter 收到消息，长度 {len(last_user)} 字符。请把 run() 替换为你的真实 agent。）",
        tool_calls=[],
    )
