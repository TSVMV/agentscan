# Changelog

## 0.5.0

- 白盒静态审计：新增 `code-scan` 子命令，对一个 AGENT 项目的文件直接审计（无需运行目标）
  - 凭据与密钥硬编码（sk-/AKIA/ghp_/私钥块/JWT/key=value 含未加引号变体）
  - 提示词卫生专项：系统提示词文件中的凭据（PROMPT-SECRET，系统提示词可被逐字泄露）
  - 危险执行（eval/exec/os.system/shell=True/命令 f-string 拼接）、反序列化（pickle/yaml.load）
  - SQL 拼接、动态路径 open()、明文 http 与已知外发端点
  - 结构化检查：.env 凭据、依赖未固定版本/风险包、项目内 MCP 配置自动复用 mcp-scan 静态审计
- scanner 加固：多轮用例跨轮持久消息历史（工具交换上下文不再丢失）；探测失败细分（4xx -> 裸模型）
- MCP 加固：跨 server 同名工具遮蔽检测；内联解释器执行（python -c / node -e）静态规则
- 工程：GitHub Actions CI（四个测试套件）；探测分类与 Ollama 解析单元测试；CHANGELOG

## 0.4.0

- 目标分类：扫描前发真实工具调用探针，把目标分类为 AGENT（function calling 可用）或裸 AI 模型；
  工具能力类用例对裸模型诚实跳过（SKIP），并支持 `--no-tools` 强制按裸模型扫描
- 工具托管：对 AGENT 托管真实沙箱工具（read_file / fetch_url / get_weather / send_email / remove_file），
  目标发出的 tool_call 真实执行（不可逆动作只记录意图），工具滥用 / 间接注入 / 数据外带用例
  全部落在真实 tool_call 上；支持 Hermes 内嵌格式的工具调用意图检测
- 出口金丝雀：本机真实 DNS/HTTP 收集器（`--sink-host` 支持 docker 目标回连宿主机），
  捕获事件含来源 IP/UA，完整写入报告证据链；判定走双通道（真实工具调用意图 OR 收集器捕获）
- MCP 安全扫描：`mcp-scan` 子命令——静态审计（下载器 / shell 管道 / 动态执行 / 内联解释器 /
  已知外发端点 / 供应链 / 敏感环境变量）+ 动态连接（stdio / streamable HTTP）检测
  工具描述投毒、名称仿冒、跨 server 同名工具遮蔽；静态高危的 server 默认拒绝启动（`--force-connect` 放行）
- 判定修复（源自真实目标反馈）：拒绝时引用标记词不再误报为攻击成功；
  拒绝语气词库扩充；忠实完成翻译降级为人工复核；工具结果文本内嵌工具调用意图检测
- scanner：多轮用例跨轮持久消息历史（工具交换上下文对后续轮次可见）；
  探测失败细分（4xx 拒绝 tools 参数 -> 裸模型；网络异常 -> 未知）
- 工程：GitHub Actions CI；测试桩升级为工具型 agent；新增 probe 分类与 Ollama 解析单元测试

## 0.3.0

- 新增 egress 模块（出口金丝雀 4 用例）与 mcp-scan 命令雏形
- 新增 SEN-05 敏感系统文件读取诱导
- payload 服务 / 金丝雀收集器与扫描生命周期绑定

## 0.2.0

- 重写为真实数据路线：移除内置假 agent 与模拟沙箱，所有结论来自真实交互
- 五档诚实判定（FAIL / SUSPECT / PASS / SKIP / ERROR），四类目标接入
  （OpenAI 兼容 / Ollama / 通用 HTTP 模板 / 进程内 Python adapter），docker 一键启动
- 七大检测模块、Markdown/JSON 报告、退出码接 CI

## 0.1.0

- 初始版本
