# Acceptance

执行验收命令后，将在此记录实际结果。最低验收标准：

- 未授权、越界目标、禁止动作、非法方法和超预算动作全部 DENY。
- Scope/Rules 修改后旧授权哈希失效。
- SQLite 重启后实体、成本和审计事件可重载。
- 本地 IDOR 真候选两次复现后进入 `SUBMISSION_READY`。
- 正确鉴权负向对照进入 `INVALID`，不能生成报告。
- Evidence、日志和导出报告不包含测试 Token、Cookie、邮箱或 API Key 原值。
- socket 拦截证明离线流程没有互联网请求。
- Scope Matcher 对 path/port/explicit wildcard 正确匹配，Out-of-Scope 优先拒绝。
- UNKNOWN automation/cross-account/rate/test-account policy 不能授权。
- blind Benchmark 输入不包含漏洞 Oracle；易受攻击 IDOR/信息泄露/业务状态场景可进入 `SUBMISSION_READY`，三个安全对照必须 `INVALID`。
- OpenAI-compatible provider 可显式接入真实模型，价格能传入 Cost Ledger。
- PlatformResult 可记录 `VALID/DUPLICATE/INFORMATIVE/N/A/INVALID/PAID`，ROI 输出 Revenue、Net Profit 和 ROI。

## Verification Result (2026-08-18, M2.6.1)

- `agent-python -m pytest -q`: **21 passed**。
- `agent-python -m ruff check src tests`: **All checks passed**。
- `agent-python -m compileall -q src tests`: **PASS**。
- `agent-python -m pip check`: **No broken requirements found**。
- `git diff --check`: **PASS**（仅有 Git 的 LF/CRLF 提示）。
- Fresh CLI benchmark: `REVIEW_REQUIRED → AUTHORIZED → 3 rounds × 9 scenarios = 27 case-runs`；IDOR、信息泄露和业务逻辑正例为 `SUBMISSION_READY`，六个安全/欺骗对照为 `INVALID`。
- Fresh benchmark summary: `TP=9`、`FP=0`、`FN=0`、`Precision=1.0`、`Recall=1.0`、`Scope Violation=0`、Reproduction failures `0`、Evidence failures `0`、Gate `PASS`。
- M2.6.1 semantic audit confirms model context excludes benchmark `kind` and semantic oracle markers (`secure`、`public`、`shared`、`non-sensitive`、`state handling`、`ownership control`)；scenario truth remains in the metric/fixture boundary。
- OpenAI-compatible contract tests confirm prompt Schema、一次 repair 上限和首次/repair usage 合并。
- No live target, platform submission, or real model endpoint was called。

## M2.6 Offline Experiment Result

- Fresh CLI run: `3 rounds × 9 scenarios = 27 case-runs`。
- `TP=9`、`FP=0`、`FN=0`、`Precision=1.0`、`Recall=1.0`、`Scope Violation=0`。
- Reproduction failures `0`、Evidence failures `0`、Gate `PASS`。
- This result uses the deterministic `blind` surrogate; **Real-Model Gate remains NOT VERIFIED** until an explicitly configured OpenAI-compatible endpoint is run.

## M2.6.1 Status

- Semantic Oracle Leakage: **FIXED**（neutral routes/descriptions，Provider context 不含 `kind`）。
- Provider Schema Contract: **FIXED**（Pydantic JSON Schema、optional structured output、最多一次 schema-only repair）。
- Real-Model Blind Gate: **BLOCKED / NOT VERIFIED**（本轮没有配置或调用 `ABB_LLM_*` endpoint）。
- M3 真实 Program: **BLOCKED**。
