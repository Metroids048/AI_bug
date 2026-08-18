---
topic: skills_memory_rag
use_for: [knowledge_builder, planner]
source_tier: 3
confidence: high
sources:
  - https://www.bilibili.com/video/BV1KR596KEGB/
---

# Skills、Memory 与知识库

## 三者职责分开

### Skill

一类任务的可复用方法：
- Access Control 测试；
- API Recon；
- Report Writing；
- JS Endpoint Mining。

### Program Memory

只属于某个 Program：
- 当前 Scope；
- 特殊规则；
- 历史接受/拒绝；
- 产品结构；
- 已验证资产。

### Knowledge Base / RAG

跨 Program 可复用的知识：
- 官方安全概念；
- 高质量公开案例；
- 视频方法论；
- 失败样本；
- 报告规则。

## 从资料提炼 Skill

公开视频《黑客专属 Claude Code Skills 完整指南》强调：高质量原始资料优于杂乱网页拼接，应把大部头测试指南提炼为可复用 Skill，并给出上下文与原因，而不是只保留命令。

## 对 AI_bug 的原则

不要把 465 页资料整个塞 Prompt。

应该先拆：

```text
知识源
→ 主题
→ 判断规则
→ 正样本
→ 反样本
→ 验证模板
→ Skill / RAG chunk
```

## RAG 偏差

历史报告越多，不一定越好。

公开视频复盘里，模型因为历史报告中 IDOR 太多而过度追 IDOR。

所以知识库必须保留：
- Accepted；
- Failed Hypothesis；
- Safe Control；
- Informative/N/A；
- Duplicate；
- 不同漏洞类型的平衡。
