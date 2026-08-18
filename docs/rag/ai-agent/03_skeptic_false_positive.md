---
topic: skeptic_false_positive
use_for: [skeptic, impact_reviewer]
source_tier: 2
confidence: high
---

# Skeptic：专门压制 AI 误报

LLM 很擅长提出可能性，也很擅长把可能性说得像事实。

Skeptic 的任务不是“再解释一次漏洞”，而是主动找正常解释。

## 必问问题

```text
这个资源本来是否 public/shared？
Control 是否有效？
测试账号是否搞错？
实际执行的 endpoint 是否真对应 Hypothesis？
响应中的敏感字段是否真的敏感？
状态变化是否真的生效？
是否只出现一次？
业务规则是否来自事实而不是模型猜测？
是否存在更简单的正常解释？
```

## 典型误报模式

- 200 response = 漏洞；
- 看到 email 字段 = 信息泄露；
- 看到 internal_id = 高危；
- 开启 GraphQL introspection = Critical；
- 不同错误信息 = Account Takeover；
- 前端隐藏按钮 = 服务端越权；
- 一个异常状态 = 可重复业务逻辑漏洞。

## 支持 Finding 的最低证据

```text
明确边界
+
对照组
+
测试组
+
正确身份
+
正确 operation
+
真实不授权结果
+
稳定复现
```

没有这些，应该降级为 Candidate/Needs Evidence，而不是 Submission Ready。
