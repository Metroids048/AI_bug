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

## Verification Result (2026-08-18, M2.6.4)

- **M2.6.4 OFFLINE GATE INTEGRITY: PASS**（fresh SQLite，3 rounds × 9 scenarios = 27 case-runs）。
- `agent-python -m pytest -q`: **68 passed**。
- `agent-python -m ruff check src tests`: **All checks passed**。
- `agent-python -m compileall -q src tests`: **PASS**。
- `agent-python -m pip check`: **No broken requirements found**。
- `git diff --check`: **PASS**。
- Fresh blind result: `COMPLETED`, `TP=9`, `FP=0`, `FN=0`, `precision=1.0`, `recall=1.0`, `contract_failures=0`, `semantic_contract_failures=0`, `scope_violations=0`, `reproduction_failures=0`, `evidence_failures=0`, `gate_passed=true`。
- Exact batch integrity now rejects missing batch identity, RUNNING/incomplete batches, requested-round mismatch, missing/duplicate scenarios, incomplete runs, and foreign run/case borrowing.
- Hidden semantic contracts reject same-account fake IDOR, different-resource fake IDOR, different-code replay, and cross-account replay plans; information contracts distinguish safe fields from scenario-defined sensitive fields.
- Oracle isolation covers Provider context and benchmark ValidationPlan prompt/schema; `expected_status` is not exposed to a real benchmark validator model.
- Verification commit: `5b4fc1f`
- Real-Model Gate: **NOT VERIFIED**（本轮没有配置或调用 `ABB_LLM_*` endpoint）。
- M3 live target: **BLOCKED**。

## Earlier Verification Result (2026-08-18, M2.6.3)

- M2.6.3 Gate Integrity implemented: exact ExperimentBatch isolation, structured operation/plan contract, execution target audit, and dynamic plan-derived reports.
- `agent-python -m pytest -q`: **50 passed**。
- Verification commit: `de7b424`
- `agent-python -m ruff check src tests`: **All checks passed**。
- `agent-python -m compileall -q src tests`: **PASS**。
- `agent-python -m pip check`: **No broken requirements found**。
- `git diff --check`: **PASS**（仅有 Git 的 LF/CRLF 提示）。
- Fresh offline Batch A `cff1bcd4-85a0-499e-a680-93af8520f04d`: `COMPLETED`, `runs=3`, `case_runs=27`, `TP=9`, `FP=0`, `FN=0`, `contract_failures=0`, `scope=0`, `reproduction_failures=0`, `evidence_failures=0`, `gate=true`。
- Fresh offline Batch B `0207287b-9e78-438b-b473-d644ecb400ae`: independent `runs=1`, `case_runs=9`, `gate=false`, `insufficient_rounds`; exact batch summary did not borrow Batch A history。
- Scenario mismatch regression: declared `GET /api/documents/{id}` with environment plan returned `SCENARIO_MISMATCH`, executed targets empty, and did not score documents TP。
- Real-Model Gate: **NOT VERIFIED**（本轮没有配置或调用 `ABB_LLM_*` endpoint）。

## Earlier Verification Result (2026-08-18, M2.6.2)

- `agent-python -m pytest -q`: **22 passed**。
- `agent-python -m ruff check src tests`: **All checks passed**。
- `agent-python -m compileall -q src tests`: **PASS**。
- `agent-python -m pip check`: **No broken requirements found**。
- `git diff --check`: **PASS**（仅有 Git 的 LF/CRLF 提示）。
- Fresh CLI benchmark: `REVIEW_REQUIRED → AUTHORIZED → 3 rounds × 9 scenarios = 27 case-runs`；IDOR、信息泄露和业务逻辑正例为 `SUBMISSION_READY`，六个安全/欺骗对照为 `INVALID`。
- Fresh benchmark summary: `TP=9`、`FP=0`、`FN=0`、`Precision=1.0`、`Recall=1.0`、`Scope Violation=0`、Reproduction failures `0`、Evidence failures `0`、Gate `PASS`。
- M2.6.1 semantic audit confirms model context excludes benchmark `kind` and semantic oracle markers (`secure`、`public`、`shared`、`non-sensitive`、`state handling`、`ownership control`)；scenario truth remains in the metric/fixture boundary。
- OpenAI-compatible contract tests confirm prompt Schema、一次 repair 上限和首次/repair usage 合并。
- Research fixture context tests confirm the model receives only researcher-owned accounts, neutral resource IDs (`doc-a`、`item-a`、`record-a`、`item-1`) and `WELCOME`; no expected status, safe/vulnerable label, security conclusion, or `shared-doc` marker is present。
- No live target, platform submission, or real model endpoint was called。

## M2.6 Offline Experiment Result

- Fresh CLI run: `3 rounds × 9 scenarios = 27 case-runs`。
- `TP=9`、`FP=0`、`FN=0`、`Precision=1.0`、`Recall=1.0`、`Scope Violation=0`。
- Reproduction failures `0`、Evidence failures `0`、Gate `PASS`。
- This result uses the deterministic `blind` surrogate; **Real-Model Gate remains NOT VERIFIED** until an explicitly configured OpenAI-compatible endpoint is run.

## M2.6.2 Status

- Semantic Oracle Leakage: **FIXED**（neutral routes/descriptions，Provider context 不含 `kind`）。
- Provider Schema Contract: **FIXED**（Pydantic JSON Schema、optional structured output、最多一次 schema-only repair）。
- Research Fixture Metadata: **FIXED**（structured accounts/resources/inputs；`record-a` replaces `shared-doc`）。
- Real-Model Blind Gate: **BLOCKED / NOT VERIFIED**（本轮没有配置或调用 `ABB_LLM_*` endpoint）。
- M3 真实 Program: **BLOCKED**。
