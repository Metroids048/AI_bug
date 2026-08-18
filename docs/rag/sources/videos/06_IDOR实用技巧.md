---
title: 高效查找 IDOR 漏洞的实用技巧
source_url: https://www.bilibili.com/video/BV16VdvYjEe7/
source_tier: 3
confidence: high
---

# 高效查找 IDOR：提炼稿

视频给出的核心不是某个 Payload，而是一个可重复的流程：

```text
准备两个独立用户环境
↓
完整使用应用、点击功能
↓
从 HTTP history 找包含对象变量的请求
↓
识别认证方式
↓
保持用户 A 的认证
↓
替换为用户 B 的对象引用
↓
比较是否得到 B 的敏感数据
```

## 对 Agent 最有价值的点

1. 不要只盯 URL；变量可能在 API body/header 等位置。
2. 先通过正常 UI 产生真实请求。
3. 确定认证信息到底是什么，避免把 Session 搞混。
4. 跨用户测试要有两个研究员控制的账号。
5. 判断依据是“是否得到本不该得到的数据/操作”，不是状态码。

## 可直接转成 Validator 模板

```yaml
control_actor: account_a
control_resource_owner: account_a
test_actor: account_a
test_resource_owner: account_b
mutable_field: object_reference
expected_test: deny_or_public_only
```
