---
topic: authorization_scope
use_for: [planner, validator, executor, reporter]
source_tier: 1
confidence: high
sources:
  - https://docs.hackerone.com/en/articles/8494552-defining-scope
  - https://docs.hackerone.com/en/articles/8495670-scope-best-practices
  - https://docs.bugcrowd.com/researchers/participating-in-program/reviewing-bounty-briefs/
---

# 授权与 Scope

## 核心规则

任何真实目标测试前，Agent 必须先回答：

```text
这个 Program 是什么？
这个具体资产是否明确 In Scope？
允许哪些测试方法？
有哪些 Out of Scope？
有没有速率、账号、自动化、数据访问、披露限制？
```

只要其中一项关键规则不明确，就不能把“不确定”解释成“允许”。

## Scope 必须结构化

建议至少保留：

```yaml
program:
platform:
asset:
asset_type:
in_scope:
bounty_eligible:
allowed_methods:
disallowed_methods:
rate_limit:
test_account_rules:
automation_rules:
data_handling_rules:
source_url:
captured_at:
policy_hash:
```

## 计划阶段

Planner 只能针对明确 In Scope 资产产生假设。

## 执行阶段

每个 Action 都重新过 ScopeGuard，不允许因为“上一步在 Scope 内”就自动推断下一步也在。

## 报告阶段

提交前再次确认：
- 受影响资产仍属于 Scope；
- 测试方法没有违反 Program Rules；
- 报告不包含不应公开的数据。

## 常见错误

- 把“公司拥有”自动等同于“In Scope”。
- 把 wildcard 理解得比官方规则更宽。
- 忽略路径级、端口级、产品级限制。
- 忽略自动化扫描、DoS、社工、真实用户数据等禁止项。
- Program 更新后仍使用旧 Policy Snapshot。

## 平台事实

Bugcrowd 的 Bounty Brief 明确包含 Targets、Scope、Rewards 和 Program Rules，要求研究员开始前阅读；Out-of-Scope 测试可能导致处罚。

HackerOne 也将具体资产、是否可奖励、资产类型和 Scope 分开管理。Agent 必须使用当次采集到的真实规则，而不是凭历史经验猜。
