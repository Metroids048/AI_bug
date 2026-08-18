---
topic: information_disclosure
use_for: [planner, validator, skeptic, impact_reviewer]
source_tier: 1
confidence: high
sources:
  - https://portswigger.net/web-security/information-disclosure
---

# Information Disclosure

## 定义

应用无意中向不该获得这些信息的用户暴露敏感数据。

## 常见来源

- API 返回多余私有字段；
- 错误堆栈；
- Debug 数据；
- 备份文件；
- 源码/版本控制残留；
- 内部配置；
- 用户页面泄露隐私；
- GraphQL schema 或字段；
- JavaScript 中硬编码信息。

## 先判断“敏感不敏感”

不能因为字段名里有：

```text
internal
debug
token
id
email
```

就自动判漏洞。

需要明确：

```text
谁看到了？
正常是否应该看到？
数据真实敏感吗？
是否能进一步利用？
Program 是否接受？
```

## 真阳性信号

- 未授权用户得到真实私有字段；
- 跨用户得到 PII；
- 泄露有效秘密或认证材料；
- Debug 信息直接暴露可利用内部信息；
- 公开接口可批量获得本应受权限控制的数据。

## 误报

- 公共用户 ID；
- 非敏感 internal_id；
- 公开 profile；
- 版本信息但无额外影响；
- 静态配置并不包含秘密。

## Impact

Information Disclosure 的价值高度依赖数据本身。
“泄露了一个字段”不是 Impact 描述。
