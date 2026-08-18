---
topic: validation_evidence
use_for: [validator, executor, evidence_agent]
source_tier: 1
confidence: high
---

# 验证、复现与 Evidence

## 最基本结构

```text
CONTROL
→ 证明正常功能和身份有效

TEST
→ 只改变一个关键边界变量

COMPARE
→ 比较请求、响应、状态

REPRODUCE
→ 再做一次独立复现

EVIDENCE
→ 保存能让第三方审核的最小材料
```

## 为什么需要 Control

没有 Control 时，Agent 很容易把：
- 失效 Session；
- 服务器故障；
- 资源不存在；
- 功能本来公开；
- 网络错误；

误判为安全问题。

## Evidence 至少记录

```yaml
timestamp:
asset:
method:
operation:
actor_account:
resource_owner:
request_shape:
response_status:
relevant_response_fields:
before_state:
after_state:
scope_decision:
redactions:
```

敏感令牌和密钥要脱敏，不把认证凭据直接写入长期知识库。

## 不要仅凭状态码

`200` 不一定说明越权；
`403` 也不一定说明安全。

必须看：
- 返回的数据是谁的；
- 操作是否真正生效；
- 状态是否发生变化；
- 业务规则到底是什么。

## 复现

Submission-ready 结果应该来自稳定复现，而不是一次偶然响应。
