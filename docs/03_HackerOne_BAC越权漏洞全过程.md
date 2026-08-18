---
title: HackerOne漏洞挖掘实战：发现BAC越权漏洞全过程
creator: 王尼互
duration: "43:23"
source_fidelity: medium
topic: broken_access_control
---

# HackerOne BAC 越权漏洞全过程

## 先理解 BAC 是什么

BAC = Broken Access Control，中文可以直接理解为：

> **系统没有正确检查“你有没有资格做这件事”。**

它包含很多具体表现：

- A 用户看到 B 用户的数据；
- 普通用户调用管理员接口；
- 没登录也能访问登录后内容；
- 没权限修改的数据可以直接通过 API 修改；
- 免费用户能使用高级权限；
- 已被移除的用户还能继续访问。

IDOR 是 BAC 中最常见的一类。

---

# 一个 BAC 漏洞从零到成立，完整路径是这样的

```text
理解角色
↓
找到一个具体功能
↓
抓到真实请求
↓
找出“谁/什么对象”由哪些参数决定
↓
建立第二个受控账号
↓
交换对象 ID / Token / Role / 参数
↓
比较返回结果
↓
确认服务端有没有真正做权限检查
↓
复现至少两次
↓
证明数据或操作影响
↓
整理 PoC
↓
提交报告
```

---

# 第一步：先画权限关系

例如一个 SaaS：

```text
Owner
Admin
Member
Guest
```

你需要先知道正常规则：

| 操作 | Owner | Admin | Member | Guest |
|---|---:|---:|---:|---:|
| 看自己的项目 | ✓ | ✓ | ✓ | 可能 |
| 看别人私有项目 | 取决于授权 | 取决于授权 | ✗ | ✗ |
| 邀请成员 | ✓ | ✓ | ✗ | ✗ |
| 删除项目 | ✓ | 可能 | ✗ | ✗ |
| 修改账单 | ✓ | ✗ | ✗ | ✗ |

BAC 测试本质上就是：

**拿“应该不允许”的格子去实际请求。**

---

# 第二步：抓一个正常请求

不要凭空构造。

先让正常用户在 UI 里做一次操作。

例如：

```http
GET /api/projects/12345
Authorization: Bearer <A_TOKEN>
```

或者：

```http
POST /api/projects/12345/delete
Authorization: Bearer <A_TOKEN>
```

先确认这个请求在正常情况下能成功。

这叫 baseline，也就是“正常基线”。

---

# 第三步：找到权限判断可能依赖的字段

重点看：

- project_id
- user_id
- account_id
- organization_id
- workspace_id
- owner_id
- role
- tenant_id
- UUID
- GraphQL node id

不要只改 URL。

对象身份可能藏在：

```text
URL
Query 参数
JSON body
Header
Cookie
GraphQL variables
JWT
```

---

# 第四步：用第二个账号做真正的权限测试

假设：

```text
Account A 拥有 Project A
Account B 拥有 Project B
```

测试：

```text
A_TOKEN + Project_B_ID
```

如果系统仍返回 B 的数据：

```text
HTTP 200
+
B 的真实私有内容
```

那么非常接近水平越权。

如果 A 能修改 B：

```text
PATCH /api/projects/B
Authorization: A_TOKEN
```

并且 B 的项目真的发生改变，影响更明确。

---

# 第五步：不要只看状态码

错误做法：

```text
200 = 有漏洞
403 = 没漏洞
```

实际要比较：

- Response body；
- 数据字段；
- 响应长度；
- 操作是否真实生效；
- B 账号重新登录后的状态；
- 后台是否真的保存；
- 是否只是缓存/假响应。

最重要的是：

**最终系统状态有没有发生不该发生的变化。**

---

# 第六步：区分“对象存在性泄露”和真正 BAC

例如：

```text
ID 不存在 → 404
ID 存在但无权限 → 403
```

这能让攻击者判断某个 ID 是否存在。

这叫存在性 Oracle。

它可能是一个线索，但不一定单独值钱。

真正有价值的是继续问：

```text
知道 ID 存在以后
↓
能不能读？
能不能改？
能不能删除？
能不能把它加入攻击链？
```

---

# 第七步：横向越权和纵向越权要分开

## 横向

同等级用户之间越权。

```text
普通用户 A
→ 读取普通用户 B 的数据
```

## 纵向

低权限变成高权限。

```text
Member
→ 调用 Admin 功能
```

一般来说，如果能：
- 获得管理员能力；
- 修改敏感设置；
- 管理其他用户；
- 访问组织级数据；

影响往往更大。

---

# 第八步：不要用真实受害者验证

安全的测试方式：

```text
Account A = 自己
Account B = 自己
```

如果必须验证删除、修改、转移等高风险动作：

- 只操作自己控制的测试对象；
- 尽量选择可恢复动作；
- 操作前保存 Evidence；
- 不要批量执行；
- 不要触碰真实客户数据。

---

# 第九步：一个能提交的 BAC 报告应该有什么

## Summary

一句话说清：

> 低权限用户可以通过修改 `project_id` 读取另一个用户的私有项目。

## Preconditions

说明需要什么：

- 两个普通账号；
- 已登录；
- Project B 属于 Account B。

## Steps

步骤必须能让审核人员照着做。

例如：

1. A 登录。
2. B 创建私有 Project B。
3. A 正常请求自己的 Project A。
4. 把请求里的 `project_id` 换成 Project B。
5. 保持 A 的认证信息不变。
6. 重发。
7. 返回 Project B 的私有内容。

## Expected

服务端应该返回 403/404，不能返回 B 的数据。

## Actual

服务端返回了完整数据。

## Impact

攻击者可遍历其他用户对象并读取敏感数据。

---

# 第十步：为什么 BAC 特别适合 AI

因为它很适合做“差异测试”。

AI 可以自动：

```text
A账号请求
vs
B账号请求
```

比较：
- endpoint；
- ID；
- role；
- cookie；
- response；
- 状态变化。

然后生成大量这样的测试矩阵：

```text
role × endpoint × object owner × method
```

例如：

| Role | Endpoint | Owner | Expected |
|---|---|---|---|
| Member | GET /project/1 | self | allow |
| Member | GET /project/2 | other | deny |
| Member | DELETE /project/2 | other | deny |
| Admin | GET /project/2 | same org | allow/按规则 |
| Guest | GET /project/2 | private | deny |

这比模型漫无目的“找漏洞”可靠得多。

---

# AI最容易犯的 5 个错误

1. 只看到 200 就说“发现 Critical”。
2. 没有第二测试账号，却猜测别人数据能访问。
3. 测试了 endpoint B，却把结果记到 endpoint A。
4. 修改数据后没有验证最终状态。
5. 为了证明影响执行破坏性操作。

所以正确 Gate 应该要求：

```text
正确 Scenario
+
正确执行 Endpoint
+
两个受控身份
+
稳定复现
+
真实影响
```

---

# 最少术语

- BAC：权限检查失效。
- IDOR：通过修改对象 ID 访问别人的对象。
- Horizontal：同权限等级用户之间越权。
- Vertical：低权限用户获得高权限能力。
- Baseline：正常行为基准。
- PoC：最小可复现证明。

---

# 来源说明

- B站检索可确认该视频标题、作者和约 43:23 时长。
- 当前公开索引未取得完整逐字稿。
- 本文件用该视频主题对应的完整 BAC 实战链路，并用 HackerOne 官方 BAC 指南校验概念和流程。
- 不应把具体示例数字、接口名当作视频作者原始案例细节。
