# MVP Boundary

本轮 M2.5 目标是让真实模型面对未提供漏洞答案的本地 Benchmark，并验证它能发现预埋漏洞、拒绝安全对照，同时保持所有请求在 local lab。

包含：Scope Matcher v2、ProgramPolicySnapshot、UNKNOWN 默认拒绝、ProviderFactory、OpenAI-compatible Research、结构化 ValidationPlan、六场景 Benchmark、两次复现、脱敏 Evidence、Real Skeptic/Impact Review、确定性 Final Gate、PlatformResult/Bounty Ledger、成本和 Replay、CI。

不包含：真实目标测试、Mass Recon、自动扩大 Scope、自动提交、Dashboard、Vector DB、Redis、队列、Kubernetes、跨 Program 学习和多 Agent 并发。
