# AI Bug Bounty Researcher

这是一个安全优先的离线 MVP，用于验证“AI 研究假设 + 客观验证证据 + 对抗审查”是否能形成可回放的研究闭环。

本轮只运行进程内 `lab://idor` 靶场。任何 `http://`、`https://` 或未知目标都会被执行器拒绝；系统不会扫描真实网站，也不会自动提交平台报告。

## Setup

使用全局 Agent Python 安装开发依赖：

```powershell
agent-python -m pip install -e ".[dev]"
```

## Offline happy path

```powershell
abb demo-create --db data/demo.sqlite3
abb authorize <PROGRAM_ID> <SCOPE_HASH> --db data/demo.sqlite3
abb plan <PROGRAM_ID> --db data/demo.sqlite3
abb run <PROGRAM_ID> --limit 2 --db data/demo.sqlite3
abb report <SUBMISSION_READY_FINDING_ID> --db data/demo.sqlite3
abb roi --db data/demo.sqlite3
abb audit-replay --db data/demo.sqlite3
```

`demo-create` 只创建 `REVIEW_REQUIRED` Program。必须人工确认 Scope 哈希后才能授权。

## Optional model endpoint

默认使用离线确定性 Provider。OpenAI-compatible 适配器支持 DeepSeek、CC Switch 或其他兼容中转，但必须显式启用模型网络；密钥只通过环境变量提供，不会持久化。真实模型 smoke test 不是自动验收的一部分。

## Verification

```powershell
agent-python -m pytest -q
agent-python -m ruff check src tests
```

更多边界见 [docs/SAFETY.md](docs/SAFETY.md)，验收项见 [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)。
