# Architecture

```text
Raw Policy Snapshot + Parsed Scope
        ↓ human authorization
Scope Matcher v2 + Scope Guard
        ↓ Action Proposal / ALLOW
ExperimentBatch → Research Agent → structured Hypothesis(operation method/path) → ValidationPlan
        ↓ exact batch identity + integrity ↓ hidden semantic contract
        ↓ exact batch summary              ↓ CONTROL/TEST contract
        → Offline LocalLabExecutor → Observation request audit
        ↓ Control/Test Observations
Evidence Store (redacted + stable pseudonyms)
        ↓ two clean reproductions
Real Skeptic/Impact Review + deterministic gates
        ↓
Submission-ready Finding → Report Draft → Human Submit
```

模块边界：

- `domain.py` 只定义类型、状态和快照哈希，不执行动作。
- `storage.py` 负责 SQLite 事务、实体重载、成本记录和审计回放。
- `policy.py` 是所有主动动作的最终否决点。
- `lab.py` 只允许进程内 `lab://idor`/`lab://benchmark`，不提供互联网传输。
- `providers.py` 将 blind benchmark、fixture provider 和 OpenAI-compatible provider 分开；真实模型主链通过 ProviderFactory 进入。
- `workflow.py` 编排 Planner、ValidationPlan、Evidence 和 Judge，不绕过 Policy；benchmark plan 在任何 ActionProposal 前做 operation/phase/identity 合同校验。
- `experiments.py` 为每次运行创建独立 `ExperimentBatch`；批次保存 public operation manifest 和 contract version，Summary 只能计算显式 batch identity，legacy unbatched rows 可读但不具备 Gate 资格。
- `benchmark_contracts.py` 独立实现 `BatchIntegrityValidator` 和场景语义裁决。Batch validator 校验完成状态、连续 round、9 场景 manifest、实体归属和 version；authorization、information、business contract 在 observation 之后以隐藏 Oracle 裁决语义，不进入 Provider context。
- `reporting.py` 只接受 `SUBMISSION_READY` Finding，并从 Finding → Hypothesis → ValidationPlan steps → redacted Observation Evidence 动态生成报告。

Scope/Rules/原始 Policy 发生变化时授权哈希失效。数据库只保存脱敏证据、稳定身份伪名和结构化决策。
