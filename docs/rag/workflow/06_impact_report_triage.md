---
topic: impact_report_triage
use_for: [impact_reviewer, reporter, learning_agent]
source_tier: 1
confidence: high
sources:
  - https://docs.hackerone.com/en/articles/8475116-quality-reports
  - https://docs.hackerone.com/en/articles/8475055-report-components
  - https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/
---

# Impact、报告与 Triage

## Impact 分两层

```text
Observed Impact
= 已经通过当前测试证明的结果

Potential Impact
= 如果攻击链继续成立，理论上可能扩大到的结果
```

报告里不能把 Potential 当成已经发生的事实。

## 高质量报告最少包含

1. 清晰标题；
2. 受影响资产；
3. 前置条件；
4. 逐步复现；
5. Expected vs Actual；
6. 已观察 Impact；
7. 请求/响应/截图等支持材料；
8. 必要的安全脱敏。

HackerOne 官方强调“完整但简洁”，审核人员必须能够快速理解和复现。

## Triage 是重要训练数据

最终状态应回写：

```text
VALID / TRIAGED
DUPLICATE
INFORMATIVE
N/A
INVALID
```

并保存原因。

## 为什么负样本重要

只喂 Accepted 报告，会把模型训练成“任何异常都值得提交”。

应该同时学习：
- 为什么报告被判 Duplicate；
- 为什么只有 Informative；
- 哪些缺 Impact；
- 哪些无法复现；
- 哪些实际上符合正常业务。
