# Architecture

```text
Raw Policy Snapshot + Parsed Scope
        ↓ human authorization
Scope Matcher v2 + Scope Guard
        ↓ Action Proposal / ALLOW
Research Agent → ValidationPlan → Offline LocalLabExecutor
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
- `workflow.py` 编排 Planner、ValidationPlan、Evidence 和 Judge，不绕过 Policy。
- `reporting.py` 只接受 `SUBMISSION_READY` Finding。

Scope/Rules/原始 Policy 发生变化时授权哈希失效。数据库只保存脱敏证据、稳定身份伪名和结构化决策。
