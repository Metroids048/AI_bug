---
topic: glossary
use_for: [all]
source_tier: 1
---

# 必要术语

| 术语 | 给 Agent 的准确含义 |
|---|---|
| Program | 厂商在 HackerOne/Bugcrowd/SRC 上公布的安全项目。 |
| Scope | 明确允许测试的资产、方法和限制。Scope 是执行前置条件，不是建议。 |
| Out of Scope | 明确禁止测试或不接受报告的范围。 |
| Target | 当前实际研究的一个网站、API、应用或授权资产。 |
| Recon | 在不越界的前提下理解资产、功能、接口和技术表面。 |
| Finding | 一个值得调查的异常，不等于漏洞。 |
| Vulnerability | 已通过证据证明违反安全边界的问题。 |
| Impact | 漏洞能造成的真实安全后果。 |
| PoC | 最小、可复现、足以证明问题的证据链。 |
| Triage | 平台/厂商验证、分类和定级报告的过程。 |
| Duplicate | 同一问题已经有人更早提交。 |
| Informative | 有信息价值，但通常不足以构成可奖励漏洞。 |
| N/A | Not Applicable，不符合有效漏洞标准。 |
| BAC | Broken Access Control，权限控制失效。 |
| IDOR | 通过对象引用访问/修改本不属于当前用户的对象，是 BAC 常见子类。 |
| Authentication | 确认“你是谁”。 |
| Authorization | 确认“你能做什么”。 |
| Session | 服务器识别同一个登录用户连续请求的机制。 |
| API | 程序之间交互的接口。 |
| Endpoint | 一个具体 API 操作地址/入口。 |
| GraphQL | 一种以 schema、query、mutation 为核心的 API 方式。 |
| Seed Request | 已从真实、授权操作中取得并验证有效的一条请求，作为后续研究起点。 |
| Safe Control | 正常应该成功或正常应该被拒绝的对照操作，用来降低误报。 |
| Oracle | 响应差异泄露了某种事实，但自身不一定构成可奖励漏洞。 |
