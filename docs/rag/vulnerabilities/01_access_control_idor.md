---
topic: access_control_idor
use_for: [planner, validator, skeptic, impact_reviewer]
source_tier: 1
confidence: high
sources:
  - https://portswigger.net/web-security/access-control
  - https://www.bilibili.com/video/BV16VdvYjEe7/
  - https://www.bilibili.com/video/BV11SCZBjEi5/
---

# Access Control / IDOR

## 定义

Authentication 解决“你是谁”；
Authorization / Access Control 解决“你能不能做这件事”。

BAC 是服务端没有正确执行权限限制。

IDOR 是 BAC 的常见形式：客户端提供某个对象引用，服务端没有正确验证当前用户是否有权访问该对象。

## 三类

- Horizontal：同等级用户之间越权。
- Vertical：低权限获得高权限能力。
- Context-dependent：在错误业务状态下执行本应禁止的动作。

## 最可靠测试模式

```text
A 登录
↓
A 正常访问 A 自己的对象（Control）
↓
准备 B 自己控制的对象
↓
保持 A 的认证不变
↓
只替换对象引用为 B 的对象
↓
比较响应与最终状态
```

## 可变对象引用可能出现的位置

- URL path
- query parameter
- JSON body
- GraphQL variables
- header
- cookie
- nested object

## 真阳性信号

- A 得到 B 的私有数据；
- A 修改/删除 B 的对象；
- Member 执行 Admin 才能执行的动作；
- 已移除成员仍可访问组织资源。

## 常见误报

- 对象本来就是 public；
- 对象明确 shared with A；
- 响应只有公共字段；
- 只是错误信息不同；
- 只知道对象存在，但无法越权读取或操作；
- Account A/B 搞混。

## Agent Gate

必须绑定：

```text
Scenario
→ Hypothesis
→ ValidationPlan
→ 实际执行 Operation
→ Observation
```

不能“假设 Documents、实际测 Environment、最后把结果记到 Documents”。
