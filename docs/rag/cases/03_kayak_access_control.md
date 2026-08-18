---
topic: case_access_control
source_tier: 2
confidence: high
source: https://www.hackerone.com/blog/how-improper-access-control-vulnerability-led-account-theft-one-click
---

# 案例：KAYAK Improper Access Control

## 为什么收录

HackerOne 官方以 KAYAK 的公开报告作为 Improper Access Control 的真实案例，说明权限问题可能从一个看似局部的错误扩大到账户级影响。

## Agent 应学习的不是原始攻击细节，而是链路

```text
不正确的访问控制
↓
攻击者获得本不应有的操作能力
↓
操作能够影响另一账户
↓
最终形成账户级安全影响
```

## 判断原则

高 Impact 不能只靠漏洞分类名。

要证明：
- 谁可以触发；
- 对谁生效；
- 需要什么交互；
- 最终账号/数据状态发生了什么；
- 是否稳定复现。
