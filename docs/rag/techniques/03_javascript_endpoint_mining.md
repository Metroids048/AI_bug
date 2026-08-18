---
topic: javascript_endpoint_mining
use_for: [recon_agent, planner]
source_tier: 3
confidence: medium_high
---

# JavaScript / Hidden Endpoint Mining

前端 JavaScript 经常包含 UI 没直接展示的：
- API path；
- feature flag；
- 旧功能；
- GraphQL operation；
- route；
- 参数名；
- 内部产品名。

## Agent 目标

不是“看到字符串就报信息泄露”。

正确输出应是：

```yaml
endpoint:
source_file:
method_if_known:
parameters:
auth_context_if_known:
ui_usage:
confidence:
why_interesting:
```

## 后续验证

1. 先确认 endpoint 是否真实存在；
2. 是否属于当前 Scope；
3. 是否需要认证；
4. 正常 UI 是否已经调用；
5. 是否有权限/业务边界；
6. 再形成 Hypothesis。

## 常见错误

- 把 sourcemap/JS 中路径直接当漏洞；
- 调用不属于 Scope 的第三方服务；
- 对旧 endpoint 做高强度扫描；
- 把开发环境地址和生产地址混淆。
