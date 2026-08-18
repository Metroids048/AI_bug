---
topic: non_destructive_testing
use_for: [validator, executor, skeptic]
source_tier: 2
confidence: high
---

# 非破坏性验证

漏洞赏金的目标是证明安全边界被突破，不是把影响做大到最大。

## 默认原则

```text
Evidence First
Minimal Proof
Researcher-Controlled Data Only
Stop Before Irreversible Action
```

## 优先级

1. 先读取，不写入。
2. 能用测试账号证明，就不用真实用户。
3. 能用单个测试对象证明，就不批量。
4. 能通过响应证明，就不做破坏性状态改变。
5. 需要高风险动作时先停下，说明目的和替代方案。

## 两账号

权限测试优先使用：

```text
account_a = researcher-controlled attacker role
account_b = researcher-controlled victim/control role
```

不要为了验证 BAC/IDOR 去修改第三方真实用户数据。

## 破坏动作 Gate

下列动作默认需要额外审批或安全替代：

- 删除账号/组织/项目；
- 不可恢复修改；
- 大规模创建或发送；
- 资金/真实支付变化；
- 大量并发；
- 高速枚举；
- 触及真实客户隐私。

## 来自 AI 实战的教训

公开视频中的 Claude Code Bug Bounty 复盘提到过：Agent 为证明权限问题执行了删除第二测试账号的动作，后来创建账号的路径又被修复，导致研究员难以重新复现。

因此 Agent 必须把“保存可复现性”视为漏洞研究的一部分。
