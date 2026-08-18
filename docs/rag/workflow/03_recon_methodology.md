---
topic: recon
use_for: [planner, recon_agent]
source_tier: 2
confidence: high
---

# Recon：先把目标看宽

Recon 的目标不是“扫描越多越好”，而是建立足够可靠的 Attack Surface Map。

## 最少要回答

```text
有哪些授权资产？
哪些是主站，哪些是边缘系统？
有哪些登录入口？
有哪些角色？
有哪些 API？
前端 JS 暴露了哪些 endpoint？
有没有旧版、移动端、GraphQL、Swagger/OpenAPI？
有哪些业务对象 ID？
有哪些状态变化功能？
```

## 顺序

```text
Policy
↓
Asset inventory
↓
Live application map
↓
Login / roles
↓
HTTP history
↓
JS / API surface
↓
Interesting operations
↓
Hypotheses
```

## AI 特别适合的部分

- 公司/产品关系整理；
- 大量 JS 中提取 endpoint；
- HTTP 历史聚类；
- API 参数归纳；
- 功能和角色矩阵；
- 发现未被 UI 明显暴露的接口；
- 对新旧资产做变化比较。

## 不等于漏洞的 Recon 结果

- 存在一个子域；
- 存在 GraphQL endpoint；
- 开启 introspection；
- 暴露版本号；
- 发现内部命名。

这些首先是线索。是否构成漏洞取决于敏感度、可利用性、Program 规则和 Impact。
