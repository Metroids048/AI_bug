---
topic: case_information_disclosure_graphql
source_tier: 2
confidence: high
source: https://www.hackerone.com/blog/8-high-impact-bugs-and-how-hackerone-customers-avoided-breach-information-disclosure
---

# 案例：HackerOne GraphQL 信息泄露

## 抽象问题

公开案例中，GraphQL 权限控制不正确，导致攻击者能够查询本不应得到的用户敏感信息，包括多个账户相关私有字段。

## Agent 应学习

“GraphQL 存在”不是漏洞。

真正的问题是：

```text
authenticated / unauthorized caller
↓
query field/object
↓
server returns private fields
↓
field/object access control missing
```

## 验证结构

- 明确当前用户角色；
- 正常查询自己的允许字段；
- 请求不属于当前用户/权限的字段；
- 比较服务端返回；
- 只把实际返回的敏感字段记为 Observed Impact。

## Impact

由“数据敏感性 × 可访问对象范围 × 利用条件”共同决定。
