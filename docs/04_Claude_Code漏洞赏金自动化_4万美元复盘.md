---
title: 基于Claude Code的漏洞赏金自动化：从HackerOne报告到4万美元实战复盘
bilibili_creator: 王尼互
original_creator: NahamSec
guest: Archangel
original_title: My Friend Made $40,000 Using Claude Code (Here's How)
duration: "35:39"
source_fidelity: very_high
topic: ai_assisted_bug_bounty
---

# Claude Code 漏洞赏金自动化：4万美元实战复盘

## 这条视频真正讲的是什么

不是：

> “装个 Claude Code 就能自动赚 4 万美元。”

真正的方法是：

```text
研究员过去的大量真实报告
↓
提炼成漏洞 Skills
↓
建立全局 Agent 规则
↓
为每个 Program 保存独立 Memory
↓
让 Claude 做 Recon、API 理解、脚本、重复测试、长时间执行
↓
人继续纠偏
↓
新漏洞和漏掉的漏洞反向更新 Skills / Agent
```

核心不是模型本身，而是：

**把一个成熟研究员过去的经验变成可重复调用的上下文。**

---

# 1. 他先把约 2000 份历史 HackerOne 报告交给 Claude

Archangel 的做法大致是：

```text
拿到自己的 HackerOne 历史报告
↓
让 Claude 阅读
↓
找出自己过去反复发现的漏洞模式
↓
按漏洞类型生成 Skill
```

这样以后启动新会话时，Claude 不需要从零理解：

- 他喜欢找什么；
- 哪些漏洞模式常出现；
- 怎么验证；
- 怎么扩大 Impact。

并且以后出现新报告，可以继续刷新 Skill。

这个设计本质上是：

```text
历史成功经验
→ 结构化成可执行知识
```

---

# 2. Skill、Agent File、Program Memory 是三层不同东西

视频里最值得直接抄走的架构就是这三层。

## Skill：专项能力

例如：

```text
ffuf skill
blind XSS skill
RCE skill
report writing skill
```

Skill 负责：
- 某类漏洞怎么识别；
- 哪些现象值得关注；
- 怎么验证；
- 哪些攻击链常见；
- 某个工具怎么用；
- 为什么要这么做。

## Agent File：全局原则

每个新目标都会带一份默认 Agent 文件。

它定义：

```text
你是 Bug Bounty Hunter
不是普通 Pentester
目标是可证明 Impact
不要沉迷理论问题
不要把普通配置问题夸成 Critical
```

## Program Memory：当前项目经验

例如 Amazon VRP：

```text
这个 Program 的 XSS 奖励高
这个项目某类漏洞更常见
这个 Scope 有什么特殊限制
```

Memory 会根据当前 Program 不断更新。

---

# 3. “Impact First” 是整个 Agent 的核心约束

Claude 默认很容易把以下东西讲得很严重：

- CORS 配置；
- Defense in Depth；
- 理论漏洞；
- 暂时无法利用的问题；
- 普通配置错误。

但 Bug Bounty 不是安全咨询报告。

真正要问：

```text
攻击者现在能利用吗？
能造成什么实际后果？
厂商真的会为它付钱吗？
```

所以 Agent File 必须不断强调：

```text
Impact
Impact
Impact
```

这条视频里 Archangel 甚至提到，即使已经写了 Agent File，有时仍然要提醒 Claude 不要只追求“发现漏洞”。

---

# 4. Skill 要解释“为什么”，不只是给命令

视频展示的 ffuf Skill 不只是：

```text
运行 ffuf
```

而是给 Claude：
- 使用方法；
- 多个例子；
- 什么时候用；
- 为什么用；
- 什么结果值得继续。

理由很简单：

LLM 依赖上下文推理。

只有命令：

```text
do X
```

很容易机械执行。

如果告诉它：

```text
为什么 X 有价值
什么情况下 X 有价值
结果怎么解释
```

模型表现会更稳定。

---

# 5. 一个新 Target 的初始化可以很简单

Archangel 有一个很简单的命令/alias：

```text
hunt John Deere
```

它本身只是：
- 创建 Target 目录；
- 复制默认 Agent File；
- 建立对应 Workspace。

真正有价值的不是这个命令，而是启动后 Claude 已经拥有：

```text
历史报告知识
+
漏洞 Skills
+
工具 Skills
+
通用研究原则
+
当前 Program Memory
```

---

# 6. AI特别适合做 Recon

视频里拿 John Deere 做演示。

他们先不指定具体资产，而让 Claude 找：

- John Deere 的收购公司；
- 冷门资产；
- 不容易被普通猎人第一时间注意到的域名。

Claude 找到多个相关公司和资产线索。

以前研究员可能要：

```text
WHOIS
↓
新闻
↓
公司关系
↓
收购记录
↓
域名
↓
验证归属
```

现在 AI 可以大幅压缩这些信息整理工作。

但 Scope 必须最后再核验。

---

# 7. 一定要挖 JavaScript 和隐藏 Endpoint

Archangel 的 Agent File 明确要求：

```text
subdomain enumeration
probe
JS bundle mining
hidden endpoint discovery
hidden scope discovery
```

原因是他过去很多成功漏洞来自：

- JS 中隐藏 API；
- 没有 UI 的功能；
- 旧 endpoint；
- 注册接口；
- 冷门路径。

如果只是让 Claude：

```text
test this website
```

它很容易只围绕主页和几个显眼功能。

所以正确思路是：

```text
先横向看宽攻击面
↓
再深入某个功能
```

---

# 8. 历史 RAG 会产生偏见：他的 Claude 一开始疯狂找 IDOR

因为 Archangel 的过去报告里有大量 IDOR。

于是 Claude 学完后得出一个很自然的结论：

```text
过去成功最多 = IDOR
↓
以后继续疯狂找 IDOR
```

但 Archangel 认为：

> 简单整数 IDOR 自己本来就会找，没必要大量烧 Token。

所以他让 Claude 修改 Agent File：

```text
IDOR 很重要
但不要把绝大多数时间花在简单 IDOR
```

这说明：

**RAG 不是越多越好，样本分布会直接改变 Agent 行为。**

---

# 9. 漏掉的漏洞也要反向写进 Agent

Archangel 举过一个例子：

某内部 Okta 实例本来应该只给内部人员使用，却错误开放 self-signup。

Claude 当时漏掉了。

于是他让 Claude：

```text
记录这次漏检模式
↓
以后遇到 internal app + self-signup
↓
主动把它当作研究假设
```

这形成真正的学习循环：

```text
Finding / Miss
↓
Human Review
↓
Pattern
↓
Agent / Skill 更新
↓
下一个 Target
```

---

# 10. 黑盒 Target 可以先给 Claude 一个真实 Seed Request

视频后半段切到带登录的 Harvest Profit。

Claude一开始对应用的 API 不够清楚。

Archangel最终从浏览器/代理里抓了一条真实 API 请求，把完整请求给 Claude：

- endpoint；
- cookie；
- 认证；
- GraphQL query；
- 参数。

然后让 Claude从这一条真实请求继续：

```text
读 API
↓
读文档
↓
读 JS
↓
理解 GraphQL
↓
继续找问题
```

这个方法非常值得 AI_bug 使用：

**不要让模型凭空猜请求格式，优先给 verified seed。**

---

# 11. Claude 会夸大 Finding，所以必须有 Skeptic

视频里 Claude 会用类似：

```text
Massive gold mine
Jackpot
Critical
```

这种很夸张的语言。

但人类研究员并不会因此立即认为漏洞成立。

这说明 Agent 必须把：

```text
模型的兴奋程度
```

和：

```text
证据强度
```

彻底分开。

好的流程应该是：

```text
Candidate
↓
Reproduce
↓
Skeptic
↓
Impact
↓
Final Gate
```

---

# 12. “存在性 Oracle”可能只是后续攻击链的原料

Claude 在 GraphQL 探索里发现：

```text
对象不存在
```

和：

```text
对象存在但没权限
```

会返回不同结果。

这能帮助枚举有效 ID。

但单独拿出来未必有奖金价值。

真正应该继续问：

```text
能不能利用这个 Oracle 找到有效对象
↓
再和 IDOR/BAC 组合
↓
造成真实 Impact
```

所以：

```text
Finding
≠
Vulnerability
≠
Bounty
```

---

# 13. 自动执行最危险的问题：Claude真的删掉了自己的测试账号

Archangel讲了一个非常重要的事故。

大意是：

1. 他有两个测试账号；
2. Claude 找到一个高影响 IDOR；
3. 一个账号可以删除另一个；
4. Claude 执行了删除；
5. 第二测试账号没了；
6. 同时厂商又修复了前面用于创建账号的注册绕过；
7. 于是研究员自己无法重新创建第二账号复现。

最后厂商还是成功确认漏洞并奖励，但复现过程变得非常被动。

所以自动 Agent 必须有：

```text
Non-destructive policy
Evidence before mutation
Controlled account only
Dangerous action approval
Reproducibility preservation
```

---

# 14. 两个受控测试账号是权限测试的基础设施

视频明确讨论：

如果要测试：
- IDOR；
- BAC；
- 跨用户修改；
- 删除；
- 角色权限；

最好有两个自己控制的账号。

否则就容易触碰真实用户。

所以自动化系统应该把：

```text
attacker_session
victim_controlled_session
```

当作正式测试资源，而不是临时 Cookie。

---

# 15. AI最值钱的不一定是“更聪明”，而是“愿意干脏活累活”

Archangel举例：

某个漏洞需要：
- 建 webhook；
- 写 Python；
- 保持连接；
- 在连接期间修改数据；
- 不断试。

普通猎人会觉得很麻烦。

Claude可以快速把大量胶水代码和测试串起来。

因此 AI 的现实优势之一是：

> 把“人不想做但可能很值钱”的验证成本降下来。

---

# 16. 可以让 Agent 长时间跑，但 Prompt 不是 Runtime

Archangel会告诉 Claude：

```text
我睡觉了
继续找
不到早上8点别停
```

多数时候能继续工作。

但 Claude 有时还是会提前觉得“差不多了”然后总结退出。

这说明真正稳定的系统不能只靠：

```text
do not stop
```

而要有：

- Scheduler；
- Checkpoint；
- 状态；
- Retry；
- Budget；
- Stop Condition；
- Watchdog。

---

# 17. 收益数字怎么理解

Archangel自述，在最近一次 Live Hacking Event 中主要使用 Claude Code，收入约 4～5 万美元。

这应该理解为：

- 当事人经验分享；
- 不是对普通用户收益的保证；
- 成功背景里有非常深的历史漏洞经验；
- AI 是放大器，不是从零替代经验。

---

# 这条视频可以直接转成 AI_bug 的架构原则

```text
Historical Reports
→ RAG

Vulnerability Skills
→ 专项知识

Global Agent File
→ Research Policy

Program Memory
→ Program-specific Context

Target Workspace
→ 当前目标状态

Seed Request
→ Verified execution context

Finding
→ Skeptic
→ Impact
→ Reproduce
→ Gate

Miss / Bad Case
→ 回写 RAG / Skill
```

---

# 最少术语

- Skill：某一类任务的专项说明和经验。
- Agent File：长期约束 Agent 的总规则。
- Memory：当前项目积累的特殊经验。
- JS Bundle：前端网站打包出来的 JavaScript 文件。
- GraphQL：一种 API 查询方式。
- Webhook：系统发生事件时主动调用另一个地址。
- Seed Request：一条已经确认真实有效的请求，供 Agent 继续展开。

---

# 来源说明

- B站视频时长与标题已确认。
- 原视频：NahamSec，Archangel 嘉宾，35:39。
- 本文件主要依据可公开读取的完整英文转写整理，属于本学习包中来源完整度最高的一条。
