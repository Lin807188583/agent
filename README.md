# MCP CI

一个面向 MCP/Agent 项目维护者的零依赖黑盒检查器。给它一个 MCP `stdio` 启动命令或 Streamable HTTP endpoint，它会完成安全的协议探测、验证项目不变量、检查评审基线，并用稳定报告和退出码阻断 CI。

v1 完成了最初产品目标：CLI、测试规则框架和 GitHub Action 可以在 CI 中检查协议兼容、公开元数据、安全不变量和未评审漂移。项目仍保留教学可读性，但不宣称覆盖完整 MCP 规范，也不会主动执行发现到的能力。

## 立即运行

要求 Python 3.11+，没有第三方运行时依赖。CI 覆盖 Python 3.11–3.14。

```bash
cd mcp-ci-demo

# 可选：安装本地 CLI
python3 -m pip install -e .

# 正常 Server：默认阈值下应退出 0
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/good_server.py"

# 故意有问题的 Server：应退出 1
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/bad_server.py"

# 机器可读 JSON 报告
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/bad_server.py" \
  --format json

# 生成可供 CI 收集的 SARIF 文件
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/bad_server.py" \
  --format sarif \
  --output artifacts/mcp-ci.sarif

# 加载示例风险接受配置；发现仍会出现在报告中
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/bad_server.py" \
  --config examples/mcp-ci.json \
  --format json

# Terminal A：启动只监听 loopback 的教学型 Streamable HTTP Server
python3 examples/good_http_server.py --port 8000

# Terminal B：检查 HTTP endpoint
PYTHONPATH=src python3 -m mcp_ci check \
  --http "http://127.0.0.1:8000/mcp"

# 生成一次经过人工评审后提交到仓库的脱敏基线
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/good_server.py" \
  --write-baseline examples/mcp-ci-baseline.json

# 在 CI 中同时执行内置规则、项目策略和基线漂移检查
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/good_server.py" \
  --config examples/mcp-ci-policy.json \
  --baseline examples/mcp-ci-baseline.json \
  --format sarif \
  --output artifacts/mcp-ci.sarif
```

`--stdio` 与 `--http` 必须且只能选择一个。检查器使用 `shlex` 拆分 stdio 命令并直接创建子进程，不经 shell 执行。HTTP 只允许 loopback 使用明文，其他地址必须使用 HTTPS；URL 中不能嵌入用户名或密码。

`--timeout` 控制单个协议请求，默认 5 秒；`--total-timeout` 控制完整探针，默认 60 秒。两者必须是大于零的有限数。完整预算覆盖初始化、分页、两次 Tool 快照和 transport hardening 检查，耗尽时以运行错误退出，不生成半份报告。

## 有界诊断与产物写入

stdio Server 即使持续打印日志或发送 unsolicited JSON-RPC message，也不会让保留的诊断证据无限增长。报告中的 `observations.diagnostics` 分别记录总数、实际留存数和是否截断；unsolicited message 只保留 `jsonrpc`、`id`、`method` 与字段存在性，不保存任意 `params`、`result` 或 `error` body。

指定 `--output` 或 `--write-baseline` 时，MCP CI 会在目标目录写完并同步临时文件，再原子替换目标。写入失败不会用半截内容覆盖上一次通过评审的产物。

## 它实际做了什么

```text
CLI target selector
  ├─ stdio command ── JSON-RPC line transport
  └─ HTTP URL ─────── JSON / bounded SSE transport
          └─ request-id correlation
               └─ MCP safe probe
                    ├─ initialize
                    ├─ notifications/initialized
                    ├─ ping
                    ├─ tools/list（仅当声明 tools，opaque cursor，最多 20 页；完整快照 × 2）
                    ├─ resources/list（仅当声明 resources，最多 20 页）
                    ├─ resources/templates/list（同 resources capability，最多 20 页）
                    ├─ prompts/list（仅当声明 prompts，最多 20 页）
                    └─ unknown method
                         └─ deterministic rules
                              ├─ suppression policy（可选）
                              ├─ text / JSON / JUnit / SARIF report
                              └─ exit 0 / 1 / 2
```

它**不会调用任何发现到的 Tool**。`readOnlyHint` 等 annotations 只是提示，不是可以信任的授权证明；通用黑盒工具无法确认真实副作用。

## 基础规则

| ID | 类型 | 检查内容 |
|---|---|---|
| `MCP001` | 协议 | initialize 是否成功 |
| `MCP002` | 协议 | stdout 是否混入非 JSON-RPC 日志 |
| `MCP003` | 协议 | initialize 是否返回协议版本 |
| `MCP004` | 兼容 | 协商版本是否偏离 CI 基线 |
| `MCP005` | 协议 | ping 是否成功 |
| `MCP006` | 协议 | 未知方法是否返回 `-32601` |
| `MCP007` | 契约 | `tools/list` 是否返回 tools 数组 |
| `TOOL001` | 契约 | Tool 条目是否为对象 |
| `TOOL002` | 契约 | Tool 名称是否重复 |
| `TOOL003` | 兼容 | Tool 名称是否适合跨客户端使用 |
| `TOOL004` | 质量 | Tool 是否缺少描述 |
| `TOOL005` | 安全信号 | 描述是否包含可疑指令文本 |
| `SCHEMA001` | 契约 | inputSchema 是否为 object schema |
| `SCHEMA002` | 契约 | properties 是否为对象 |
| `SCHEMA003` | 契约 | required 是否引用未声明参数 |
| `SCHEMA004` | 秘密 | Schema default 是否像凭据 |
| `SCHEMA005` | 最小输入 | 是否显式拒绝未声明参数 |
| `SEC001` | 人工复核 | 疑似写操作是否缺少明确 annotations |
| `SUPPLY001` | 供应链 | 两次 Tool manifest 是否无提示漂移 |

## Capability 与分页规则

v1 会根据 `initialize.result.capabilities` 安全地调用对应的只读 list 方法：
`tools/list`、`resources/list`、`resources/templates/list` 和 `prompts/list`。它不会因为发现了 URI、Prompt 或 Tool 就继续调用 `resources/read`、`prompts/get` 或 `tools/call`。

每个 list flow 最多检查 20 页。`nextCursor` 始终被当作 opaque string，探针只把服务器原样返回的 cursor 放回下一次请求，不解析、不递增、不写入报告。重复 cursor、cursor 循环、非字符串 cursor、超过页数上限以及条目结构错误都会产生稳定发现。

| ID | 级别 | 检查内容 |
|---|---|---|
| `CAP001` | high | 已声明 capability 的 list 方法是否返回完整结果 |
| `CAP002` | high | capability 值和 initialize capabilities 是否为对象 |
| `CAP003` | medium | `listChanged` 是否为布尔值 |
| `CAP004` | medium | 声明 `listChanged` 时基础 list 方法是否可用 |
| `PAGE001` | high | `nextCursor` 是否为字符串 |
| `PAGE002` | high | cursor 是否重复或循环 |
| `PAGE003` | high | 是否超过 20 页仍持续返回 cursor |
| `PAGE004` | high | list 条目是否全部为对象 |
| `PAGE005` | high | list 集合字段是否为数组 |

这些规则检查协议与元数据形状，不读取资源内容、不解析 URI 模板，也不执行 Prompt 或 Tool。`listChanged=true` 只是服务器通知承诺；本版本记录其类型并验证基础 list 可用性，尚未维持长驻通知监听。

## v1 元数据与响应规则

| ID | 检查内容 |
|---|---|
| `RPC001`～`RPC003` | JSON-RPC 版本、result/error 互斥、错误对象结构 |
| `RES001`～`RES003` | Resource URI/name、URI 唯一性、可选字段类型 |
| `RESTPL001`～`RESTPL002` | Resource Template 必填字段、唯一性和字段类型 |
| `PROMPT001`～`PROMPT004` | Prompt 名称、唯一性、参数结构和可疑描述 |

Resource 重复发现只报告数组索引，不把原始 URI 放进报告。Prompt 与 Tool 的公开 dispatch name 会保留，便于维护者定位契约。

## 项目安全策略

`--config` 读取严格 JSON。除可过期 suppression 外，v1 可以声明：

- `allowed_protocol_versions`：允许协商的协议版本；
- `required_capabilities`：Server 必须声明的 capability；
- `required_tools`：必须存在的精确 Tool 名称；
- `forbidden_tools`：不能暴露的大小写敏感 glob；
- `max_tools`：端点最大 Tool 数；
- `require_read_only`：匹配后必须明确 `readOnlyHint=true` 的 Tool glob；
- `rules.disabled` 与 `rules.severity`：可审计规则选择和严重级别覆盖。

对应发现为 `POL001`～`POL006`。示例见 [`examples/mcp-ci-policy.json`](examples/mcp-ci-policy.json)。规则禁用会从发现列表移除，但禁用了哪些规则、影响了多少发现仍会写入 `observations.rule_controls`。

## 脱敏基线与供应链漂移

```bash
# 首次生成，人工评审后提交
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/good_server.py" \
  --write-baseline mcp-ci-baseline.json

# 后续 PR 检查
PYTHONPATH=src python3 -m mcp_ci check \
  --stdio "python3 examples/good_server.py" \
  --baseline mcp-ci-baseline.json
```

基线 schema v1 保存协议版本、capability、数量、安全标识和规范化元数据的 SHA-256。它不保存原始 Resource URI、Resource/Prompt/Tool 描述、schema 内容、session、cursor 或任何调用结果。Tool/Prompt 名称作为公开 dispatch identifier 保留，Resource 和 URI Template identity 会先哈希。

`BASE001`～`BASE005` 分别报告协议、capability、Tool、Resource 和 Prompt 漂移。`--baseline` 与 `--write-baseline` 互斥；基线生成是显式写操作，不会自动接受发现到的接口为安全。

完整稳定 ID、默认严重级别和语义见 [`docs/RULES.md`](docs/RULES.md)；严格配置字段、处理顺序和匹配规则见 [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)。

`TOOL005`、`PROMPT004`、`SEC001` 等属于**复核信号**，不能单独证明漏洞。v1 可以记录 suppression/risk acceptance，但它不会把风险接受伪装成“没有发现”。

## Streamable HTTP 规则

| ID | 级别 | 检查内容 |
|---|---|---|
| `HTTP001` | high | 恶意 Origin 是否被 403 拒绝 |
| `HTTP002` | high | initialize POST 是否得到成功状态 |
| `HTTP003` | high | 成功响应是否为可解析的 JSON 或 SSE |
| `HTTP004` | medium | notification 是否返回 202 空 body |
| `HTTP005` | medium | GET 是否返回 SSE 或 405 |
| `HTTP006` | medium | 非法 `MCP-Protocol-Version` 是否返回 400 |
| `HTTP007` | high | session ID 是否非空且只包含可见 ASCII |
| `HTTP008` | medium | 建立 session 后，缺失 session header 是否返回 400 |

HTTP 探针把协商后的协议版本和 session header 带到后续请求，并在结束时发送 DELETE 做 best-effort 清理。报告只保存 session 是否存在、长度和字符合法性，**不会保存原始 session ID**。

Session 只用于 transport 连续性，不能充当身份认证。教学 Server 没有实现 OAuth；真实远程部署必须在 session 之外验证每个请求的授权信息。

探针会读取 POST 返回的 `application/json`，也能逐个解析 `text/event-stream` data event；收到匹配 response 后立即关闭。GET 只检查响应头后关闭，不维持后台 listener。所有响应最多检查 1 MiB。

实现依据是 MCP 官方 [`2025-11-25 Transports`](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)、[`Resources`](https://modelcontextprotocol.io/specification/latest/server/resources)、[`Prompts`](https://modelcontextprotocol.io/specification/latest/server/prompts)、[`Tools`](https://modelcontextprotocol.io/specification/latest/server/tools)、[`Pagination`](https://modelcontextprotocol.io/specification/latest/server/utilities/pagination) 和 [`Security Best Practices`](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)。旧版 2024 双端点 HTTP+SSE 不在 v1 自动探测范围内。

## 可审计规则豁免

通过 `--config` 加载本地 JSON：

```json
{
  "suppressions": [
    {
      "rule_id": "SCHEMA005",
      "tool": "legacy/read",
      "reason": "Legacy compatibility; tracked in issue #123",
      "expires": "2026-10-01"
    }
  ]
}
```

- `rule_id` 和非空 `reason` 必填；
- `tool` 可选，存在时只精确匹配该 Tool 的发现；
- `expires` 可选，是包含当天的 ISO 日期，到期后不会继续生效；
- 同一个 `(rule_id, tool)` 不能重复，未知规则和错误字段会以退出码 `2` 失败；
- 匹配后的发现标记为 `suppressed`，保留证据、理由和到期日，但不参与 `--fail-on` 计算；
- 若同一发现同时命中规则级与 Tool 级配置，范围更窄的 Tool 级配置优先。

示例文件是 [`examples/mcp-ci.json`](examples/mcp-ci.json)。真实项目应让豁免理由指向 issue/风险审批记录，并使用短周期到期日。

## 报告格式

| 格式 | 用途 | 关键语义 |
|---|---|---|
| `text` | 本地阅读、终端日志 | 显示活动与已豁免发现 |
| `json` | 二次处理、自定义看板 | 保留完整结构化证据和 CI 状态 |
| `junit` | CI 测试结果面板 | 活动发现为 failure，已豁免发现为 skipped |
| `sarif` | GitHub Code Scanning 等安全结果系统 | 使用稳定 rule ID、level 和 accepted suppression |

JUnit 中每个活动发现都会显示为 failure，方便维护者逐条查看；进程退出码仍只由 `--fail-on` 阈值决定。黑盒结果没有真实源码位置，因此 SARIF 不伪造 `locations`。

默认把报告写到 stdout。指定 `--output PATH` 后会创建父目录并写入 UTF-8 文件，stdout 保持为空，便于后续 artifact/upload 步骤处理。

## CI 退出码

- `0`：没有达到 `--fail-on` 阈值的发现；
- `1`：存在达到阈值的发现；
- `2`：命令无法启动、超时或其他运行错误；
- `130`：用户中断。

默认 `--fail-on medium`。可以使用 `info`、`low`、`medium`、`high`、`critical` 或 `none`。

## GitHub Action

仓库根目录的 `action.yml` 是一个可复用 composite action。当前仓库内的工作流这样调用：

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"

- uses: ./
  with:
    stdio: python examples/good_server.py
    config: examples/mcp-ci-policy.json
    baseline: examples/mcp-ci-baseline.json
    fail-on: medium
    format: sarif
    output: artifacts/mcp-ci.sarif
```

检查已由其他 workflow step 或 service 启动的 HTTP Server 时，将 `stdio` 换成：

```yaml
with:
  http: https://staging.example.com/mcp
  fail-on: medium
  format: sarif
  output: artifacts/mcp-ci.sarif
```

`stdio` 与 `http` 必须且只能填写一个；可选输入还包括 `config`、`baseline`、`protocol-version`、`timeout`、`total-timeout`、`format` 和 `output`。发布仓库和 tag 后，`uses: ./` 才应替换为 `owner/repository@v1`。Action 输入先进入环境变量，再由 Python 入口构造 CLI 参数，避免把用户输入直接拼接进 shell 命令。

多个协议版本使用 GitHub 原生 matrix，每个 job 仍生成一份独立、容易定位的报告：

```yaml
strategy:
  matrix:
    protocol: ["2025-03-26", "2025-06-18", "2025-11-25"]
steps:
  - uses: ./
    with:
      stdio: python examples/good_server.py
      protocol-version: ${{ matrix.protocol }}
      fail-on: medium
```

不同版本可能有不同 baseline；不要用一个版本的基线自动批准另一个协议版本。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

测试分九层：

1. 报告模型、严重级别和 suppression 退出语义；
2. 乱序 JSON-RPC request-id 关联与 stdout/stderr 分离；
3. HTTP URL 策略、JSON/SSE 解析、redirect 和 session header；
4. MCP 生命周期探针与纯规则函数；
5. 项目策略、规则控制、严格配置和 suppression；
6. 基线确定性、脱敏、严格 schema 和漂移；
7. JUnit/SARIF 的可解析结构和审计字段；
8. 对 stdio/HTTP Server 启动真实进程或 socket 的端到端测试；
9. 全局预算、有界诊断、原子写入和 wheel 安装后的发布门禁。

## 建议阅读顺序

1. `examples/good_server.py`：理解最小 stdio 生命周期和 Tool contract；
2. `examples/good_http_server.py`：对照官方规范理解 Origin、状态码和 session；
3. `src/mcp_ci/transport.py`：理解 stdio request-id 关联；
4. `src/mcp_ci/http_transport.py`：理解 URL 策略、JSON/SSE 和有界读取；
5. `src/mcp_ci/probe.py`：理解 transport-neutral 生命周期和安全边界；
6. `src/mcp_ci/rules.py`：学习“证据 → 稳定规则 ID → remediation”；
7. `src/mcp_ci/config.py`：理解项目不变量、规则控制和风险接受；
8. `src/mcp_ci/baseline.py`：理解脱敏快照和漂移证据；
9. `src/mcp_ci/reporters.py`：理解同一报告模型如何映射到四种 CI 格式；
10. `src/mcp_ci/cli.py`：理解 CI 退出语义；
11. `tests/test_end_to_end.py`：看产品行为如何被自动证明。

设计与实施记录在 `docs/plans/`。

## 下一阶段，而不是现在就做

- SSE resumability、`Last-Event-ID` 与多 stream 去重；
- sampling、elicitation、Tasks profiles；
- tool-call mock/sandbox 与显式 side-effect policy；
- OAuth resource/audience/scope 安全测试；
- Gateway 重试、参数改写、缓存、租户隔离测试；
- 多 SDK/Host 的真实互操作 fixture；
- 可签名的社区规则包与 baseline provenance。

v1 已覆盖最初的维护者 CLI、规则测试框架和 GitHub Action 目标。后续功能应由真实维护者反馈驱动，不把本项目扩张成通用网关。
