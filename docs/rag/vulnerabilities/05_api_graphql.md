---
topic: api_graphql
use_for: [recon_agent, planner, validator]
source_tier: 1
confidence: high
sources:
  - https://portswigger.net/web-security/api-testing
  - https://portswigger.net/web-security/graphql
---

# API / GraphQL

## API 研究目标

前端只使用了后端能力的一部分。
Agent 要理解：

- 有哪些 endpoint；
- 支持哪些 method；
- 参数来自哪里；
- 哪些需要认证；
- 对象、角色和状态如何映射；
- 有没有旧接口、隐藏接口或文档。

## 最重要的方法：从真实请求向外扩展

优先拿 Seed Request：

```text
真实 UI 操作
↓
抓到成功请求
↓
确认 Session/参数/响应
↓
再修改一个变量研究
```

比模型凭空猜 URL 稳定得多。

## GraphQL

GraphQL 通过 schema 描述对象、字段和操作。

Agent 要关注：
- query；
- mutation；
- variables；
- object ID；
- field-level access control；
- schema 暴露；
- 不同角色是否得到不同字段。

## 重要判断

“发现 GraphQL endpoint”本身通常只是信息。
“introspection 开启”也不自动等于高危。

真正需要继续判断：
- 是否暴露私有字段；
- 是否能跨用户查询；
- mutation 是否缺权限；
- 是否能利用 schema 找到隐藏的高价值操作。

## API 错误模式

- 前端隐藏功能但 API 仍允许；
- GET 禁止但其他 method 允许；
- 一个参数有前端限制，服务端没有；
- 对象级权限只在列表接口检查，详情接口没检查。
