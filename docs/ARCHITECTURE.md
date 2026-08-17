# Architecture

```text
Program + Scope Snapshot
        ↓ human authorization
Scope Guard
        ↓ Action Proposal / ALLOW
Offline LocalLabExecutor
        ↓ Observation
Evidence Store (redacted)
        ↓ two clean reproductions
Skeptic + deterministic gates
        ↓
Submission-ready Finding → Report Draft → Human Submit
```

模块边界：

- `domain.py` 只定义类型、状态和快照哈希，不执行动作。
- `storage.py` 负责 SQLite 事务、实体重载、成本记录和审计回放。
- `policy.py` 是所有主动动作的最终否决点。
- `lab.py` 只允许进程内 `lab://idor`，不提供互联网传输。
- `workflow.py` 编排 Planner、Validator、Evidence 和 Judge，不绕过 Policy。
- `reporting.py` 只接受 `SUBMISSION_READY` Finding。

Scope/Rules 发生变化时授权哈希失效。数据库只保存脱敏证据和结构化决策。
