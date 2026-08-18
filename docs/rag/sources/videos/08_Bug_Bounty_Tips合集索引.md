---
title: Bug bounty tips / 赏金猎人合集
source_url: https://www.bilibili.com/video/BV1io4y1j7dq/
source_tier: 3
confidence: medium
---

# Bug Bounty Tips 合集：可吸收主题

该合集包含多段真实 Web / Bug Bounty 主题视频。

适合提取进 RAG 的主题包括：

- Broken Access Control；
- API/Web/Android 交叉攻击面；
- Account Takeover；
- Hidden assets；
- 从零研究真实目标；
- Subdomain takeover、CSRF、IDOR、XSS 等组合案例；
- 真实 Web App 测试方法。

## 入库规则

不要把每集的操作步骤机械保存。
只抽：

```text
入口
→ 假设
→ 关键变量
→ Control
→ Test
→ Evidence
→ Impact
→ 失败/误报点
```

每个案例必须能映射到已有漏洞类别；不能仅凭视频标题产生“成功案例”。
