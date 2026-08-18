---
title: 黑客专属 Claude Code Skills 完整指南
source_url: https://www.bilibili.com/video/BV1KR596KEGB/
original_source: ZeroDay Gym
source_tier: 3
confidence: high
---

# Claude Code Skills：安全知识提炼

这条视频最有用的观点是：

> 不要把杂乱网页直接当 Skill 原料，优先使用高质量、结构化的安全资料，再把它变成可复用的 Agent 方法。

视频示例使用大型安全测试指南，将长篇资料压缩成 Claude Code Skill。

## 对 AI_bug 的启发

知识摄入链应该是：

```text
高质量 source
↓
去掉目录/重复/营销
↓
抽“什么时候用”
↓
抽“为什么”
↓
抽“怎么判断”
↓
抽安全限制
↓
抽正例/反例
↓
生成 Skill 或 RAG chunk
```

而不是：

```text
PDF → 全文塞 Prompt
```

## Skill 最有价值的内容

- trigger；
- prerequisites；
- decision rules；
- evidence requirements；
- false-positive checks；
- safety constraints；
- output schema。

工具命令反而不是最重要的部分。
