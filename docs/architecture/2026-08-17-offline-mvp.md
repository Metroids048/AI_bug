# Offline MVP ADR

选择模块化单体 CLI、SQLite 和进程内 ASGI 靶场，原因是首个闭环的风险重点是授权、证据和可回放性，而不是并发扩展。所有主动动作由 Scope Guard 统一控制，M2 执行器继续硬拒绝真实网络目标。模型通过结构化 Provider 接口替换，默认离线假模型，兼容端点仅作为显式人工 smoke test。
