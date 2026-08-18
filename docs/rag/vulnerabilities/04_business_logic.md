---
topic: business_logic
use_for: [planner, validator, skeptic, impact_reviewer]
source_tier: 1
confidence: high
sources:
  - https://portswigger.net/web-security/logic-flaws
  - https://www.hackerone.com/blog/how-business-logic-vulnerability-led-unlimited-discount-redemption
---

# Business Logic

## 定义

应用的业务规则或状态设计允许了本不应该发生的行为。

它通常不是“输入里有危险字符”，而是：

> 合法功能被按开发者没有预料到的顺序、次数或角色组合使用。

## Agent 先抽业务不变量

例如：

```text
一次性优惠只能成功一次
订单支付后不能回到未支付
退款总额不能超过付款额
免费账户不能获得付费权益
审批人不能审批自己的申请
邀请链接只能用于指定组织/用户
```

## 测试维度

- 次数；
- 顺序；
- 状态；
- 角色；
- 金额；
- 对象所有权；
- 并发；
- 重放；
- 客户端参数信任。

## 最可靠方法

```text
先正常走完整流程
↓
记录状态变化
↓
只改变一个业务前提
↓
观察服务端是否仍接受
```

## 真实案例模式

HackerOne 官方介绍过 Stripe 的业务逻辑案例：一次性费用折扣被重复使用，导致持续获得本不应重复存在的优惠。关键不是参数本身，而是“已消费状态没有被正确约束”。

## 误报

- 官方明确允许的优惠叠加；
- 仅 UI 显示异常；
- 测试环境特殊规则；
- 只在自己账户产生无安全/经济影响的视觉差异。
