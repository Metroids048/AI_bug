---
topic: hypothesis_generation
use_for: [planner]
source_tier: 2
confidence: high
---

# 漏洞假设生成

好的 Hypothesis 必须可证伪，不能只是“这里可能有漏洞”。

## 推荐结构

```yaml
asset:
operation:
actor:
resource:
expected_security_boundary:
hypothesis:
reason:
safe_control:
test_action:
required_accounts:
risk:
potential_impact:
```

## 例：权限

不是：

> 这个接口可能 IDOR。

而是：

> 普通用户 A 对自己资源的读取是允许的；当保持 A 的 Session 不变、仅把资源引用替换成 B 自有资源时，服务端应拒绝。如果返回 B 的私有内容，则所有权检查可能缺失。

## 例：业务逻辑

不是：

> 优惠券可能有逻辑漏洞。

而是：

> 一次性优惠在第一次成功使用后应进入不可再次兑换状态；同一受控账号第二次重复提交应被拒绝。

## 评分要素

- 有明确业务/安全边界；
- 有可取得的 Safe Control；
- 测试材料属于研究员控制；
- 风险可控；
- 成功后 Impact 可证明；
- 不是仅靠状态码判断。
