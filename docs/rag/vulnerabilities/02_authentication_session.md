---
topic: authentication_session
use_for: [planner, validator, skeptic]
source_tier: 1
confidence: high
sources:
  - https://portswigger.net/web-security/authentication
---

# Authentication / Session

## 核心区别

Authentication：验证用户身份。
Authorization：登录后判断用户权限。

两个概念不能混。

## 常见研究面

- 登录流程；
- 密码重置；
- MFA / 2FA；
- Session 创建和失效；
- 登出后 Session 是否还能用；
- 账户切换；
- 邀请、注册、邮箱验证；
- OAuth / 第三方登录。

## Agent 先画状态机

```text
未登录
→ 已提交身份
→ 已验证第一因素
→ 已验证第二因素
→ 已登录
→ 已登出 / Session 失效
```

每个状态只能访问应有功能。

## 测试重点

不要只问“能不能登录”。

问：

```text
能不能跳过某一步？
凭证是否和正确用户绑定？
重置/验证 Token 是否正确绑定 Session 与账号？
登出后 Token 是否失效？
低信任状态能否访问高信任状态功能？
```

## 误报

- 登录错误信息不同但没有真实安全影响；
- Session 仅在正常超时时间内继续有效；
- 前端显示差异但服务端仍拒绝；
- 需要用户主动批准的正常流程被误判为绕过。

## Evidence

必须记录认证状态、使用的受控账号、关键状态变化和服务端结果。
