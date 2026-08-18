---
topic: ai_assisted_bug_bounty
use_for: [orchestrator, planner, learning_agent]
source_tier: 3
confidence: high
source_video: My Friend Made $40,000 Using Claude Code (Here's How)
---

# Claude Code 在 Bug Bounty 中的有效用法

公开复盘中的核心方法不是“Claude 自动扫描全网”，而是把成熟研究员已有经验变成 Agent 上下文。

## 结构

```text
Historical Reports
↓
Vulnerability / Tool Skills
↓
Global Agent Rules
↓
Program Memory
↓
Target Workspace
↓
Recon + Testing
↓
Finding / Miss
↓
反向更新知识
```

## 历史报告

研究员把大量过去 HackerOne 报告交给 Claude，让模型抽取：
- 反复出现的漏洞模式；
- 验证方式；
- Impact；
- 使用的工具；
- 思考习惯。

## Agent File

全局原则强调：

```text
Bug Bounty 目标 = Demonstrable Impact
不是 Finding 数量
```

模型很容易把普通配置、理论问题讲得过于严重，因此需要明确 Impact-first。

## Program Memory

不同 Program 的：
- Scope；
- 奖励；
- 历史漏洞；
- 技术栈；
- 高价值类型；

应该独立保存，不能全部混成通用知识。

## AI 真正的效率优势

- 读大量 JS/API；
- 写胶水脚本；
- 做繁琐重复实验；
- 长时间保持研究；
- 快速整理 Evidence；
- 把失败和漏检模式固化。

## 风险

Agent 可能：
- 过度兴奋；
- 重复追一种历史高频漏洞；
- 执行破坏操作；
- 提前停止长任务；
- 把线索直接当漏洞。

所以需要 ScopeGuard、Skeptic、Evidence、Reproduction 和执行安全边界。
