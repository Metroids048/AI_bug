---
topic: seed_request
use_for: [recon_agent, validator]
source_tier: 3
confidence: high
---

# Seed Request Expansion

## 定义

Seed Request 是从授权目标真实 UI 中抓到的一条已成功请求。

它提供可信的：
- endpoint；
- method；
- headers；
- authentication；
- content type；
- 参数结构；
- 正常 response。

## 为什么对 LLM 特别重要

没有 Seed 时，模型容易：
- 猜错 URL；
- 猜错 method；
- 漏认证；
- 幻觉参数；
- 把不存在的 API 当目标。

## 使用顺序

```text
Capture
↓
Verify baseline
↓
Normalize / redact secrets
↓
Identify mutable fields
↓
Generate safe variations
↓
Execute one variation at a time
↓
Compare
```

## 可扩展方向

- 对象 ID；
- 角色；
- method；
- body field；
- optional parameter；
- GraphQL variable；
- 业务状态。

不应该自动扩展到 Out-of-Scope host 或高风险动作。
