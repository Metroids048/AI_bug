---
title: AI Bug Bounty RAG Knowledge Base v1
purpose: 给 AI_bug 的 LLM/Agent 提供授权漏洞赏金研究所需的结构化知识
status: knowledge-only
version: 1.0
last_updated: 2026-08-18
---

# AI Bug Bounty RAG Knowledge Base v1

这不是给人从零学网安的教材，而是给 AI/Agent 用的研究知识底座。

当前阶段只做两件事：

1. 把高质量视频、官方规则、公开案例中的有效知识整理成 Markdown。
2. 建立清晰的能力目录，后续再接 Retriever / RAG / LLM。

当前仓库的真实目标执行仍应遵守项目已有安全边界；本知识库本身不改变执行权限。

## 知识优先级

```text
Tier 1  官方平台规则 / 官方测试指南
Tier 2  真实已披露报告 / 官方案例
Tier 3  高质量实战视频
Tier 4  社区经验与技巧
```

冲突时优先使用更高 Tier。

## Agent 推荐读取顺序

```text
policy/
↓
workflow/
↓
根据当前目标匹配 vulnerabilities/
↓
根据执行阶段匹配 techniques/
↓
ai-agent/
↓
cases/
```

## 目录

- `policy/`：授权、Scope、非破坏性边界。
- `workflow/`：选项目→侦察→假设→验证→证据→影响→报告。
- `vulnerabilities/`：最优先的漏洞类型知识。
- `techniques/`：跨漏洞类型都能用的执行方法。
- `ai-agent/`：Claude Code / Codex / LLM 如何参与研究。
- `cases/`：真实公开案例的抽象，不保留无关叙述。
- `sources/`：视频和官方来源清单。
- `glossary.md`：必要术语，方便 LLM 保持概念一致。

## 当前 v1 重点

优先覆盖最适合 AI 执行和当前 benchmark 的类型：

1. Access Control / IDOR
2. Authentication / Session
3. Information Disclosure
4. Business Logic
5. API / GraphQL
6. Race Condition

暂未把几十种 Web 漏洞全部展开。知识库优先追求“会判断、会验证、少误报”，而不是漏洞名数量。
