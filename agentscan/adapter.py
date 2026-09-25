"""目标接入层。

AgentScan 通过 adapter 与任意真实 agent 通信，只做一件事：
把对话历史发给目标，把目标返回的真实响应原样带回，不做任何加工。

支持四类目标：
1. OpenAICompatAdapter  —— 任何 OpenAI /chat/completions 兼容服务（OpenAI/DeepSeek/vLLM/LiteLLM/docker 部署的 agent 等）
2. OllamaAdapter        —— Ollama 原生 /api/chat
3. GenericHTTPAdapter    —— 通过 JSON 模板对接任意 HTTP 接口的 agent
4. PythonAdapter         —— 进程内直接测试（导入用户提供的 run 函数）

discover() 可对目标地址做真实探测，自动识别接口方言与可用模型。
"""

import json
from typing import Any, Optional

import requests

from .core import AgentResult, ToolCall


class AdapterError(Exception):
    """与目标通信失败，message 中携带真实错误信息。"""


class BaseAdapter:
    """目标 adapter 基类：把对话历史发给真实目标，返回真实响应。"""

    name = "base"

    def chat(self, messages: list[dict], tools: Optional[list[dict]] = None) -> AgentResult:
        raise NotImplementedError

    def list_models(self) -> list[str]:
        return []

    def followup_messages(self, res: AgentResult, tool_results: list[dict]) -> list[dict]:
        """一轮工具调用后追加回对话的消息（simple 格式，子类可覆盖）。"""
        msgs = [{"role": "assistant", "content": res.content,
                 "tool_calls": [{"id": c.call_id or "", "name": c.name, "arguments": c.arguments}
                                for c in res.tool_calls]}]
        for tr in tool_results:
            msgs.append({"role": "tool", "tool_call_id": tr["id"], "name": tr["name"], "content": tr["output"]})
        return msgs


def _http(status: int, body: str) -> AdapterError:
    return AdapterError(f"HTTP {status}: {body[:300]}")


def _tool_calls_from_openai(msg: dict) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for c in msg.get("tool_calls") or []:
        fn = c.get("function", {})
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except Exception:
            args = {"_raw": fn.get("arguments")}
        calls.append(ToolCall(name=fn.get("name", ""), arguments=args, call_id=c.get("id")))
    return calls


def _tool_calls_from_ollama(msg: dict) -> list[ToolCall]:
    """解析 Ollama 原生 message.tool_calls（arguments 可能是 dict 或 JSON 字符串）。"""
    calls: list[ToolCall] = []
    for i, c in enumerate(msg.get("tool_calls") or []):
        fn = c.get("function", {})
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args or "{}")
            except Exception:
                args = {"_raw": args}
        calls.append(ToolCall(name=fn.get("name", ""), arguments=args or {}, call_id=f"ollama_{i}"))
    return calls


def _require_http_url(url: str) -> str:
    """目标地址协议校验：仅允许 http/https（扫描目标由操作者授权指定）。"""
    if not str(url).lower().startswith(("http://", "https://")):
        raise AdapterError(f"目标地址仅允许 http/https 协议: {url}")
    return url


class OpenAICompatAdapter(BaseAdapter):
    """任何 OpenAI /chat/completions 兼容服务。base_url 需要精确到版本段，如 http://host:8000/v1。"""

    name = "openai"

    def __init__(self, base_url: str, model: str, api_key: Optional[str] = None, timeout: int = 120):
        self.base_url = _require_http_url(base_url).rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    def chat(self, messages: list[dict], tools: Optional[list[dict]] = None) -> AgentResult:
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            payload["tools"] = tools
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        try:
            resp = requests.post(self.base_url + "/chat/completions", json=payload, headers=headers, timeout=self.timeout)
        except requests.Timeout as e:
            raise AdapterError(f"请求超时（>{self.timeout}s）") from e
        except requests.ConnectionError as e:
            raise AdapterError(f"连接失败: {e}") from e
        if resp.status_code >= 400:
            raise _http(resp.status_code, resp.text)
        data = resp.json()
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError) as e:
            raise AdapterError(f"响应格式异常: {json.dumps(data)[:300]}") from e
        return AgentResult(
            content=msg.get("content") or "",
            tool_calls=_tool_calls_from_openai(msg),
            http_status=resp.status_code,
            raw=data,
        )

    def list_models(self) -> list[str]:
        headers = {}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        try:
            resp = requests.get(self.base_url + "/models", headers=headers, timeout=10)
        except Exception:
            return []
        if resp.status_code != 200:
            return []
        try:
            return [m.get("id", "") for m in resp.json().get("data", []) if m.get("id")]
        except Exception:
            return []


class OllamaAdapter(BaseAdapter):
    """Ollama 原生接口 /api/chat。"""

    name = "ollama"

    def __init__(self, base_url: str, model: str, timeout: int = 180):
        self.base_url = _require_http_url(base_url).rstrip("/")
        self.model = model
        self.timeout = timeout

    def chat(self, messages: list[dict], tools: Optional[list[dict]] = None) -> AgentResult:
        payload = {"model": self.model, "messages": messages, "stream": False}
        try:
            resp = requests.post(self.base_url + "/api/chat", json=payload, timeout=self.timeout)
        except requests.Timeout as e:
            raise AdapterError(f"请求超时（>{self.timeout}s）") from e
        except requests.ConnectionError as e:
            raise AdapterError(f"连接失败: {e}") from e
        if resp.status_code >= 400:
            raise _http(resp.status_code, resp.text)
        data = resp.json()
        msg = data.get("message", {})
        return AgentResult(content=msg.get("content") or "", http_status=resp.status_code, raw=data)

    def list_models(self) -> list[str]:
        try:
            resp = requests.get(self.base_url + "/api/tags", timeout=10)
        except Exception:
            return []
        if resp.status_code != 200:
            return []
        try:
            return [m.get("name", "") for m in resp.json().get("models", []) if m.get("name")]
        except Exception:
            return []


def _walk_path(data: Any, dotted: str) -> Any:
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


class GenericHTTPAdapter(BaseAdapter):
    """通过 JSON 模板对接任意 HTTP agent。

    config 示例:
    {
      "url": "http://127.0.0.1:9000/ask",
      "method": "POST",
      "headers": {"X-Token": "xxx"},
      "body": {"question": "{last_message}"},
      "response_content_path": "data.reply",
      "response_tool_calls_path": "tool_calls"
    }
    说明：多轮用例下，每次请求只携带当前这条用户消息，适用于无状态 agent。
    response_tool_calls_path 指向的字段格式须为 [{"name": "...", "arguments": {...}}]。
    """

    name = "generic-http"

    def __init__(self, config: dict, timeout: int = 120):
        self.config = config
        self.url = _require_http_url(str(config["url"]))
        self.method = config.get("method", "POST").upper()
        self.headers = dict(config.get("headers", {}))
        self.body = config.get("body", {"input": "{last_message}"})
        self.content_path = config.get("response_content_path", "response")
        self.tool_calls_path = config.get("response_tool_calls_path")
        self.timeout = timeout

    def chat(self, messages: list[dict], tools: Optional[list[dict]] = None) -> AgentResult:
        last_user = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")

        def fill(obj):
            if isinstance(obj, str):
                return obj.replace("{last_message}", last_user)
            if isinstance(obj, dict):
                return {k: fill(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [fill(v) for v in obj]
            return obj

        body = fill(self.body)
        try:
            if self.method == "GET":
                resp = requests.get(self.url, params=body, headers=self.headers, timeout=self.timeout)
            else:
                resp = requests.post(self.url, json=body, headers=self.headers, timeout=self.timeout)
        except requests.Timeout as e:
            raise AdapterError(f"请求超时（>{self.timeout}s）") from e
        except requests.ConnectionError as e:
            raise AdapterError(f"连接失败: {e}") from e
        if resp.status_code >= 400:
            raise _http(resp.status_code, resp.text)
        try:
            data = resp.json()
        except Exception as e:
            raise AdapterError(f"响应不是合法 JSON: {resp.text[:200]}") from e
        content = _walk_path(data, self.content_path)
        calls: list[ToolCall] = []
        if self.tool_calls_path:
            for i, c in enumerate(_walk_path(data, self.tool_calls_path) or []):
                calls.append(ToolCall(name=c.get("name", ""), arguments=c.get("arguments", {}), call_id=str(i)))
        return AgentResult(
            content=content if isinstance(content, str) else json.dumps(content, ensure_ascii=False),
            tool_calls=calls,
            http_status=resp.status_code,
            raw=data,
        )


class PythonAdapter(BaseAdapter):
    """进程内测试：用户提供 run(messages, tools=None) -> str | dict | AgentResult。

    dict 返回格式: {"content": str, "tool_calls": [{"name": ..., "arguments": {...}}]}
    """

    name = "python"

    def __init__(self, fn, label: str = "python-adapter"):
        self.fn = fn
        self.label = label

    def chat(self, messages: list[dict], tools: Optional[list[dict]] = None) -> AgentResult:
        out = self.fn([dict(m) for m in messages], tools=tools)
        if isinstance(out, AgentResult):
            return out
        if isinstance(out, str):
            return AgentResult(content=out)
        if isinstance(out, dict):
            calls = [ToolCall(name=c.get("name", ""), arguments=c.get("arguments", {}), call_id=str(i))
                     for i, c in enumerate(out.get("tool_calls", []))]
            return AgentResult(content=out.get("content", ""), tool_calls=calls)
        raise AdapterError("PythonAdapter 的 run() 返回类型不支持，须为 str/dict/AgentResult")


# ---------------------------------------------------------------------------
# 真实探测：识别目标说的是哪种"方言"
# ---------------------------------------------------------------------------

def discover(url: str, api_key: Optional[str] = None, timeout: int = 15) -> dict:
    """对目标地址做真实 HTTP 探测，返回接口识别结果。

    返回结构:
    {
      "url": 原始地址,
      "alive": 是否有任何 HTTP 响应,
      "server": Server 响应头,
      "openai_base": 识别出的 OpenAI 兼容 base（含 /v1）,
      "ollama": 是否为 Ollama 原生接口,
      "models": 探测到的模型列表,
      "notes": [探测过程记录]
    }
    """
    url = url.rstrip("/")
    info: dict[str, Any] = {"url": url, "alive": False, "server": None, "openai_base": None,
                            "ollama": False, "models": [], "notes": []}
    headers = {}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key

    root = None
    try:
        root = requests.get(url, headers=headers, timeout=timeout)
        info["alive"] = True
        info["server"] = root.headers.get("Server")
        info["notes"].append(f"GET {url} -> HTTP {root.status_code}")
    except requests.ConnectionError:
        info["notes"].append(f"GET {url} -> 连接失败（目标未启动或地址错误）")
        return info
    except Exception as e:
        info["notes"].append(f"GET {url} -> {type(e).__name__}: {e}")

    # OpenAI 兼容：先试 /v1/models 再试 /models
    for base in (url + "/v1", url):
        try:
            r = requests.get(base + "/models", headers=headers, timeout=timeout)
            info["notes"].append(f"GET {base}/models -> HTTP {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                ids = [m.get("id", "") for m in data.get("data", []) if isinstance(m, dict) and m.get("id")]
                info["openai_base"] = base
                info["models"] = ids
                break
        except Exception as e:
            info["notes"].append(f"GET {base}/models -> {type(e).__name__}")

    # Ollama 原生
    try:
        r = requests.get(url + "/api/tags", timeout=timeout)
        info["notes"].append(f"GET {url}/api/tags -> HTTP {r.status_code}")
        if r.status_code == 200:
            names = [m.get("name", "") for m in r.json().get("models", []) if m.get("name")]
            info["ollama"] = True
            if names and not info["models"]:
                info["models"] = names
    except Exception as e:
        info["notes"].append(f"GET {url}/api/tags -> {type(e).__name__}")

    return info


def build_adapter(url: str, model: Optional[str], api_key: Optional[str], api: str, timeout: int):
    """按方言构造 adapter；api=auto 时使用探测结果。"""
    if api == "ollama":
        base = url.rstrip("/")
        if not model:
            models = OllamaAdapter(base, model or "x").list_models()
            if not models:
                raise SystemExit(f"Ollama 接口未探测到已安装模型，请用 --model 指定。地址: {base}")
            model = models[0]
        return OllamaAdapter(base, model, timeout=timeout)

    info = discover(url, api_key=api_key)
    base = info.get("openai_base")
    if base is None:
        raise SystemExit(
            "未能在目标上识别出 OpenAI 兼容接口（尝试了 /v1/models 与 /models）。\n"
            "探测记录:\n  " + "\n  ".join(info["notes"]) +
            "\n若是 Ollama 请加 --api ollama；若是自定义接口请使用 --config 模板接入。"
        )
    if not model:
        models = info.get("models") or OpenAICompatAdapter(base, model or "x", api_key=api_key).list_models()
        if not models:
            raise SystemExit(f"目标未返回模型列表，请用 --model 显式指定。base={base}")
        model = models[0]
    return OpenAICompatAdapter(base, model, api_key=api_key, timeout=timeout)
