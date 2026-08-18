---
topic: end_to_end_workflow
use_for: [planner, orchestrator]
source_tier: 1
confidence: high
---

# Bug Bounty 端到端工作流

```text
平台 / Program
↓
读取 Policy + Scope
↓
Target Selection
↓
Recon
↓
Attack Surface Map
↓
Hypothesis
↓
Safe Control
↓
Validation Plan
↓
Scope Guard
↓
Execute
↓
Observation
↓
Evidence
↓
Reproduce
↓
Skeptic
↓
Impact
↓
Report Draft
↓
Human Review
↓
Submit
↓
Triage
↓
VALID / DUPLICATE / INFORMATIVE / N/A
↓
Bounty / Feedback
↓
回写知识库
```

## 每个阶段的产物

| 阶段 | 输出 |
|---|---|
| Policy | 可执行的 Scope Snapshot |
| Target Selection | 为什么值得投入当前目标 |
| Recon | 资产/功能/API/角色地图 |
| Hypothesis | 可证伪的安全边界假设 |
| Validation | 对照组 + 测试组 |
| Execution | 原始 Observation |
| Evidence | 可审计请求、响应、状态 |
| Reproduce | 至少稳定重复 |
| Skeptic | 反例、正常解释、误报可能 |
| Impact | 已观察影响与潜在影响分离 |
| Report | 审核人员能重现的最小报告 |
| Triage Result | 成功/失败原因 |
| Learning | 新 Pattern / Bad Case |

## 绝不能跳过的三道门

1. Scope Gate
2. Evidence/Reproduction Gate
3. Impact/Skeptic Gate

“模型觉得像漏洞”不能替代任何一道门。
