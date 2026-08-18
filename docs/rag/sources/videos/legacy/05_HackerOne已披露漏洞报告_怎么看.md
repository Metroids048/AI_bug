---
title: 如何查看 HackerOne 已披露的漏洞报告
creator: 犀利的远哥
duration: "33:20"
source_fidelity: high_for_platform_workflow
topic: hacktivity_learning
---

# 如何查看 HackerOne 已披露漏洞报告

## 这条内容为什么重要

Bug Bounty 最有效的学习方式之一不是看漏洞百科，而是直接看：

> **真实研究员找到了什么、怎么证明、厂商怎么处理、最后为什么成立。**

HackerOne 的公开报告主要可以通过 Hacktivity 学习。

---

# Hacktivity 是什么

可以把它理解为 HackerOne 的“漏洞动态广场”。

里面会出现：
- 已关闭报告；
- 已披露报告；
- 获得奖金的报告；
- 获得奖励/周边的报告；
- 一部分未公开细节但能看到活动的报告。

真正用来学习完整漏洞的重点是：

```text
Disclosed
```

也就是厂商已经同意公开的报告。

---

# 怎么筛出真正值得看的报告

不要首页随便点。

更高效的方式是按以下维度筛：

## 1. 按漏洞类型

例如：
- Broken Access Control；
- IDOR；
- XSS；
- SSRF；
- Authentication；
- Business Logic；
- Information Disclosure；
- Race Condition。

你现在最应该先看：

```text
BAC / IDOR
Authentication
Information Disclosure
Business Logic
```

## 2. 按 Program

如果准备长期研究某个 Program：

```text
先读这个 Program 过去已经公开的报告
```

你会直接知道：
- 历史上什么类型的漏洞出现过；
- 哪些资产容易出问题；
- 哪些问题已经被报烂；
- 厂商如何评价影响；
- 他们重视什么。

## 3. 按 Popular / New

- Popular：社区关注度更高，通常更适合先学。
- New：看最近刚出现的新报告。

---

# 一个公开报告具体要看什么

不要从第一行一路读到底。

按下面顺序读效率最高。

---

# 1. Title：先判断漏洞是什么

标题应该回答：

```text
什么地方
+
什么问题
+
造成什么后果
```

例如：

> Broken Access Control allows member to read another workspace's private data

从标题就能知道：
- 漏洞类型；
- 角色；
- 对象；
- 影响。

---

# 2. Summary：先看作者如何用几句话说明问题

好的 Summary 应该快速回答：

- 谁可以攻击？
- 需要什么条件？
- 攻击哪个功能？
- 正常应该怎样？
- 实际发生了什么？
- 最终影响是什么？

你以后训练 Report Agent 时，可以大量学这个结构。

---

# 3. Weakness / Severity：知道平台怎么归类

HackerOne 报告里通常会有：
- Weakness；
- Severity；
- CVSS（部分报告）。

不要一开始纠结分数。

先看：

> 厂商最后认为它属于什么问题、为什么重要。

---

# 4. Steps to Reproduce：这是最值得学习的部分

真正高价值的信息往往在这里。

你要拆成：

```text
前置条件
↓
正常操作
↓
抓到请求
↓
修改哪里
↓
重发
↓
出现什么结果
```

例如：

```text
1. 创建 A / B 两个测试账号
2. B 创建私有对象
3. A 抓自己的请求
4. 替换 object_id
5. 保持 A 的 token
6. 返回 B 的数据
```

这个顺序本身就可以直接变成 Agent 的 ValidationPlan 模板。

---

# 5. PoC：作者到底用什么证明

PoC 不只是代码。

可以是：
- 一条 HTTP 请求；
- curl；
- Burp 请求；
- Python 脚本；
- 截图；
- 演示视频；
- 两个账号前后状态；
- 服务器回调。

核心判断：

> 如果把这份 PoC 给另一个研究员，他能不能复现？

---

# 6. Impact：为什么厂商应该在意

这一段决定“安全异常”能不能变成“漏洞”。

典型 Impact：

- 泄露别人的私有信息；
- 修改别人的数据；
- 删除；
- 权限提升；
- 账户接管；
- 绕过付款；
- 绕过限制；
- 任意代码执行。

学习时要把：

```text
技术现象
```

翻译成：

```text
攻击者最终可以做什么
```

---

# 7. Timeline：看厂商和研究员怎么沟通

这是很多新手完全忽略的知识。

Timeline 会显示：
- 提交；
- Needs More Info；
- Triaged；
- Bounty；
- Resolved；
- Duplicate；
- Informative；
- Disclosure；
- 评论往来。

非常值得观察：

## 哪些报告一次就通过

通常：
- 步骤清楚；
- Evidence 足；
- Impact 明确。

## 哪些被反复要求补充

通常：
- 没法复现；
- 条件不清；
- 影响说不明白；
- 漏了关键请求；
- 环境不一致。

## 哪些最后 N/A / Informative

这对 RAG 尤其重要。

因为这些是：

> **“看起来像漏洞，但最终没拿到有效结论”的负样本。**

---

# 8. Bounty：别只看金额，要看“为什么”

同类型漏洞奖金可能差很多。

决定奖金的不只是漏洞名，还包括：

- 影响数据敏感度；
- 受影响用户数量；
- 是否需要用户交互；
- 攻击复杂度；
- 权限前置条件；
- 能不能链成更严重结果；
- Program 自己的奖励表。

所以不要让 RAG 学成：

```text
IDOR = $X
XSS = $Y
```

正确的是：

```text
漏洞模式
+
影响范围
+
利用条件
+
Program Policy
→ 价值判断
```

---

# 怎么用公开报告训练自己

每看一份报告，只回答 7 个问题：

1. **入口是什么？**
2. **研究员最先看到的异常是什么？**
3. **他修改了哪一个关键东西？**
4. **为什么这说明权限/逻辑出错？**
5. **怎么证明不是偶发现象？**
6. **最终真实 Impact 是什么？**
7. **如果让 AI 找，它需要提前知道哪些知识？**

这样读 20 份比看 20 小时泛网安课程更接近 Bug Bounty。

---

# 怎么转成 AI_bug RAG

不要把整份报告直接扔进去。

建议抽成统一结构：

```yaml
report_id:
program:
asset:
weakness:
roles:
preconditions:
entry_point:
normal_behavior:
mutation:
observed_behavior:
impact:
reproduction:
evidence:
triage_result:
bounty:
failure_or_success_reason:
```

然后分别建立：

```text
Accepted Findings
Duplicate
Informative
N/A
Safe Controls
```

这样模型才能同时学习：

- 什么算真漏洞；
- 什么不算；
- 什么已经被大量报过；
- 什么证据不够。

---

# Hacktivity 现在还能怎么搜

HackerOne 官方当前提供：

- Popular；
- New；
- Bug Bounty；
- Published；
- Disclosed；
- 按关注的 Hacker；
- Collaborations。

还可以通过 CWE / CVE Discovery 查看某类漏洞和相关公开报告。

其中你最该用：

```text
Disclosed
+
指定 Weakness
+
指定 Program
```

---

# 报告状态极简理解

| 状态 | 白话 |
|---|---|
| New | 刚提交 |
| Needs more info | 厂商要求补材料 |
| Triaged | 初步认为有效 |
| Resolved | 已修复/处理完成 |
| Duplicate | 别人已经先报 |
| Informative | 有信息，但通常不算有效漏洞 |
| Not Applicable | 不符合有效漏洞标准 |

---

# 学公开报告最容易犯的错误

## 1. 只收藏 Payload

Payload 不是核心。

真正要学的是：

```text
为什么研究员会想到这里？
```

## 2. 只看奖金最大的报告

高奖金漏洞通常很难复现到自己的目标。

新手更应该大量看：
- BAC；
- IDOR；
- Authentication；
- Business Logic；
- Information Disclosure。

## 3. 只收成功报告

这会把 RAG 训练成“什么都觉得有漏洞”。

应该同时收：
- Duplicate；
- Informative；
- N/A；
- 被要求补信息的报告。

## 4. 把历史报告照抄到新目标

公开报告是模式，不是万能 Payload。

正确用法：

```text
过去发生过什么
↓
抽象成漏洞模式
↓
看当前目标有没有类似条件
↓
重新验证
```

---

# 最后只记一句

**Hacktivity 的真正价值，不是看别人赚了多少钱，而是把真实漏洞的“发现→验证→Impact→Triage”全过程变成你的训练数据。**

---

# 来源说明

- B站检索可确认该视频标题、作者与约 33:20 时长。
- 该视频主题是 HackerOne 已披露报告的查看与学习。
- 平台功能和字段部分使用 HackerOne 官方 Hacktivity / Report Components / Submitting Reports 文档做了当前校验，因此这一部分适合直接进入 RAG。
