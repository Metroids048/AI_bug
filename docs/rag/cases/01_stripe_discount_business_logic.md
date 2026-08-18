---
topic: case_business_logic
source_tier: 2
confidence: high
source: https://www.hackerone.com/blog/how-business-logic-vulnerability-led-unlimited-discount-redemption
---

# 案例：Stripe 重复折扣业务逻辑

## 抽象问题

某种本应有使用次数限制的费用优惠，可以被重复兑换，从而持续获得不应重复存在的折扣。

## Agent 应学习的模式

```text
Business Rule
= benefit can be consumed only under allowed state

Control
= first valid redemption succeeds

Test
= repeat same benefit after state should be consumed

Vulnerability
= server accepts repeated redemption

Impact
= economic/business restriction bypass
```

## 关键点

这不是靠特殊 Payload。
重点是状态机：

```text
unused
→ redeemed
→ should become unavailable
```

如果第二次仍成功，才说明状态约束可能有问题。

## 误报控制

必须先确认：
- Program 真正的优惠规则；
- 是否允许多次；
- 是否针对不同交易；
- 是否测试环境特殊行为。
