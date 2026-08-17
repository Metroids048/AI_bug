# Acceptance

执行验收命令后，将在此记录实际结果。最低验收标准：

- 未授权、越界目标、禁止动作、非法方法和超预算动作全部 DENY。
- Scope/Rules 修改后旧授权哈希失效。
- SQLite 重启后实体、成本和审计事件可重载。
- 本地 IDOR 真候选两次复现后进入 `SUBMISSION_READY`。
- 正确鉴权负向对照进入 `INVALID`，不能生成报告。
- Evidence、日志和导出报告不包含测试 Token、Cookie、邮箱或 API Key 原值。
- socket 拦截证明离线流程没有互联网请求。

## Verification Result (2026-08-17)

- `agent-python -m pytest -q`: **9 passed**。
- `agent-python -m ruff check src tests`: **All checks passed**。
- `agent-python -m compileall -q src tests`: **PASS**。
- CLI E2E: `REVIEW_REQUIRED → AUTHORIZED → 5 hypotheses → 2 runs`；真 IDOR 为 `SUBMISSION_READY`，正确鉴权对照为 `INVALID`。
- Report export and `audit-replay` completed from a fresh SQLite database。
- No live target, platform submission, or real model endpoint was called。
