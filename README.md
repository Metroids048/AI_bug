# AI Bug Bounty Researcher

这是一个安全优先的离线 M2.6.4，用于验证“真实模型研究 + 客观验证证据 + 对抗审查”是否能形成可回放的研究闭环。当前已实现 Real-Model Gate Integrity、结构化 operation attribution、执行审计、批次完整性和隐藏语义契约；真实模型 Gate 尚未验证。

当前 Benchmark 运行进程内 `lab://benchmark` 靶场，包含 IDOR、信息泄露和业务状态的易受攻击/安全对照。任何 `http://`、`https://` 或未知目标都会被执行器拒绝；系统不会扫描真实网站，也不会自动提交平台报告。

## Setup

使用全局 Agent Python 安装开发依赖：

```powershell
agent-python -m pip install -e ".[dev]"
```

## Offline happy path

```powershell
abb benchmark-create --db data/benchmark.sqlite3
abb authorize <PROGRAM_ID> <SCOPE_HASH> --db data/benchmark.sqlite3
abb plan <PROGRAM_ID> --provider blind --db data/benchmark.sqlite3
abb run <PROGRAM_ID> --provider blind --limit 6 --db data/benchmark.sqlite3
abb report <SUBMISSION_READY_FINDING_ID> --db data/benchmark.sqlite3
abb platform-result <FINDING_ID> <PROGRAM_ID> <SUBMISSION_ID> --status PAID --reward 125 --db data/benchmark.sqlite3
abb roi --db data/benchmark.sqlite3
abb audit-replay --db data/benchmark.sqlite3
```

`benchmark-create` 只创建 `REVIEW_REQUIRED` Program。必须人工确认 Scope 哈希后才能授权。`program-create` 对自动化、跨账户测试、速率和测试账户规则默认保存为 `UNKNOWN`；任何 UNKNOWN 都不能授权。

## M2.6 blind experiment

```powershell
abb experiment-run <PROGRAM_ID> --provider blind --rounds 3 --db data/benchmark.sqlite3
abb experiment-list --program-id <PROGRAM_ID> --db data/benchmark.sqlite3
abb experiment-summary --batch-id <BATCH_ID> --program-id <PROGRAM_ID> --db data/benchmark.sqlite3
```

每次 `experiment-run` 都创建独立 `ExperimentBatch`；每轮都会重排 9 个本地场景并创建新的 Planner context。Summary 必须按明确 batch 计算；同一 Program 存在多个 batch 时不会自动合并。输出 TP、FP、FN、Precision、Recall、Scope Violation、Contract、Reproduction、Evidence、Token、Cost 和 Gate。`blind` 只用于离线回归，不代表真实模型能力。

## M2.6.4 Gate integrity

Gate summary 必须显式传入 `--batch-id`；没有批次身份时只能得到 fail-closed 结果，CLI 不会自动选择历史批次。被选批次必须是 `COMPLETED`，完成至少 3 个连续且唯一的 round，每个 round 恰好包含当前 manifest 的 9 个唯一场景；run、case、program 和 batch 身份必须逐项一致，缺失 completed timestamp、外部实体借用或 benchmark version 不匹配都会失败。

`benchmark_contracts.py` 保存隐藏的语义裁决：authorization 要求同一资源、资源所有者 control 和不同 test 账户；business replay 要求同一账户、同一 payload 和同一 code；information 只对场景定义的敏感字段计泄露，普通字段不会触发 finding。语义 contract、fixture truth 和 evaluation 不会进入 Provider context、模型 prompt 或 expected-status schema。

M2.6.4 的离线 Gate 结果只有在 fresh SQLite 完整跑完指定批次且所有场景通过语义实验时才可为 PASS；这不等于真实模型能力验证。Real-Model Gate 仍为 **NOT VERIFIED**，M3 live target 仍冻结。

Benchmark hypotheses 必须声明公开 operation 的 method/path；ValidationPlan 的 CONTROL/TEST steps 必须解析到同一个 operation，执行后的 method/target 从 Observation 审计。报告步骤来自 ValidationPlan，Evidence 仅输出已脱敏内容。

M2.6.1 已移除模型可见输入中的 `kind`、漏洞/安全标签、带有安全结论的路径和描述；M2.6.2 进一步提供中性的 researcher-owned `test_resources` 和 `test_inputs`（例如 `doc-a`、`item-a`、`record-a`、`WELCOME`），避免因缺少合法测试材料产生假 FN。Ground Truth 只保留在实验指标边界。OpenAI-compatible Provider 会把目标 Pydantic JSON Schema 放进提示词，可选发送 `response_format=json_schema`，并在 Schema 校验失败时最多进行一次不补充业务答案的修复请求。

## Optional model endpoint

真实 Research 通过 `--provider openai-compatible` 接入 DeepSeek、CC Switch 或其他兼容中转；必须显式设置 `ABB_LLM_NETWORK_ENABLED=true`、`ABB_LLM_API_KEY`、`ABB_LLM_BASE_URL`、`ABB_LLM_MODEL` 和价格环境变量，然后运行同一条 `experiment-run --rounds 3`。模型 API 可联网，但 Target Executor 仍只接受 `lab://benchmark`；缺少 usage 或价格会记录为 UNKNOWN，Real-Model Gate 不得宣称通过。

Program Policy Snapshot 保存原始规则、来源 URL、采集时间、Policy Hash、解析 Scope/Out-of-Scope 和规则快照。Scope Matcher 支持 scheme、host、port、显式 host/path wildcard，并且 Out-of-Scope 优先级高于 In-Scope。

## Verification

```powershell
agent-python -m pytest -q
agent-python -m ruff check src tests
```

更多边界见 [docs/SAFETY.md](docs/SAFETY.md)，验收项见 [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)。
