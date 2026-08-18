---
title: SRC 业务逻辑系列
source_urls:
  - https://www.bilibili.com/video/BV1aP411T7Xv/
  - https://www.bilibili.com/video/BV1ZXp3e1E79/
  - https://www.bilibili.com/video/BV1YW4y1n7TM/
source_tier: 3
confidence: medium
---

# SRC 业务逻辑系列：知识抽取索引

课程/案例中反复出现的业务逻辑主题：

- 验证码与用户绑定；
- 验证步骤是否可跳过；
- Token 与用户/Session 绑定；
- 任意用户登录；
- 越权；
- 支付逻辑；
- 条件竞争；
- 状态绕过。

## RAG 应吸收的不是“绕过口诀”

应把每个主题转成业务不变量：

```text
verification_credential must bind to correct user/session
one_time_state must become consumed
payment_amount must match server-side order state
privileged_action must require correct role
sequence must not allow skipping mandatory step
```

## 必须由 Tier 1 校验

这类课程存在营销成分，且部分内容年代较早。
具体平台规则和漏洞定义必须以 HackerOne/Bugcrowd/PortSwigger 当前资料为准。
