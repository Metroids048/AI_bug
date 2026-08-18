---
topic: two_account_testing
use_for: [validator, executor]
source_tier: 2
confidence: high
---

# Two-Account Differential Testing

这是 BAC/IDOR 最重要的基础测试模式。

## 准备

```text
Account A
Account B
```

都必须是研究员控制的测试账号。

## 建立资源

- A 创建 resource_A；
- B 创建 resource_B；
- 记录 owner、ID、角色。

## 测试矩阵

```text
A_session + A_resource = allow control
B_session + B_resource = allow control
A_session + B_resource = should deny
B_session + A_resource = should deny
```

如果还有 Admin/Member：

```text
role × operation × resource_owner
```

## 保持单变量

做跨账号测试时：
- Session 保持 A；
- method 不变；
- endpoint 不变；
- 只替换 resource identifier。

这样最容易解释结果。

## 错误

- A/B Cookie 混掉；
- B 资源其实共享给 A；
- 对象本来公共；
- 两次请求不是同一 operation；
- 成功响应里其实没有 B 私有数据。
