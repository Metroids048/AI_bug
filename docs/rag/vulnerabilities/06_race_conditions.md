---
topic: race_conditions
use_for: [planner, validator]
source_tier: 1
confidence: high
sources:
  - https://portswigger.net/web-security/race-conditions
---

# Race Condition / 条件竞争

## 白话定义

系统认为两个动作会“按顺序发生”，但多个请求几乎同时到达时，可能在状态更新完成前都通过检查。

## 适合关注的业务

- 一次性优惠；
- 库存；
- 付款/退款；
- 转账；
- 密码重置；
- 邀请/注册；
- 次数限制；
- 领取奖励。

## Agent 先找状态边界

```text
check
↓
action
↓
update state
```

如果多个请求可能在 `update state` 前都完成 `check`，才值得形成 Race Hypothesis。

## 安全限制

并发测试很容易产生：
- 资源滥用；
- 大量请求；
- 重复交易；
- 不可逆状态。

因此真实 Program 必须明确允许；默认在本地实验或研究员自有测试对象上验证。

## Evidence

不仅要保存“多个 200”，还要证明：
- 一个正常请求本应只成功一次；
- 并发后实际产生多个成功状态；
- 最终业务状态违反规则。
