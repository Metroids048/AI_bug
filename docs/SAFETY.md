# Safety Boundaries

- 默认不访问任何真实互联网目标。
- M2.5 执行器只接受 `lab://idor` 或 `lab://benchmark`，非 `lab` scheme 一律 `LiveTargetBlocked`。
- 不实现 DoS、压力测试、凭证填充、真实支付、真实数据修改/删除、横向移动、持久化、恶意软件或批量数据访问。
- Program 必须处于 `AUTHORIZED` 或 `ACTIVE`，且授权哈希必须匹配当前 Scope/Rules 快照。
- Scope 只匹配显式 origin，不根据 DNS、子域、CDN、跳转、JavaScript 或搜索结果扩大范围。
- Scope Matcher 同时匹配 scheme、host、port 和 path；wildcard 必须显式写在 Scope 中，Out-of-Scope 优先拒绝。
- `automation_allowed`、`cross_account_testing`、`rate_limit_per_minute` 和 `test_account_rules` 为 UNKNOWN 时不能授权。
- Program 授权必须绑定完整 ProgramPolicySnapshot，原始规则或解析结果变化会使旧授权失效。
- Evidence 只保存脱敏副本；发现 Token、Cookie、Secret、密码、API Key 或 PII 无法可靠清理时拒绝持久化。
- 不自动提交任何平台报告。报告生成后必须由人阅读并提交。
- 模型网络与目标执行完全分离，模型网络默认关闭；模型密钥不写入日志或数据库。
- Final Gate 由程序确定性执行，模型只能提供 Planner、Validator Planner、Skeptic 和 Impact Reviewer 意见。
