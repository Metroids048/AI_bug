---
topic: program_target_selection
use_for: [planner]
source_tier: 2
confidence: medium_high
---

# Program 与 Target 选择

目标不是找“最有名的网站”，而是找投入产出更合理的授权目标。

## Agent 应评估

```yaml
scope_size:
asset_freshness:
product_complexity:
roles_and_permissions:
api_surface:
recent_changes:
acquisitions_or_new_products:
competition:
known_issue_density:
reward_rules:
research_fit:
```

## 优先线索

- 新产品、新模块、新 API；
- 收购后的资产；
- 冷门子系统；
- 有多角色、多租户的 SaaS；
- Web + API + App 共用后端；
- 复杂业务状态；
- Program 有明确奖金和较清晰规则。

## 不要机械评分

高奖金 Program 不一定最适合。
大型热门主站可能竞争极高；小而复杂的业务系统反而更适合长期研究。

## 从公开报告学习 Program

Hacktivity 可以按 Program 和 Weakness 查已披露报告。

Agent 应抽取：
- 历史高频漏洞类型；
- 容易出问题的资产；
- 厂商看重的 Impact；
- 已被报烂的模式；
- 报告质量要求。

这些属于 Program Memory，不应该写成全局真理。
