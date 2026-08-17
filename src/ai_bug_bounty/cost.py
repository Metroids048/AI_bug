from __future__ import annotations

from .domain import CostEntry, ProviderUsage
from .storage import Repository


def record_usage(
    repository: Repository,
    provider: str,
    model: str,
    task: str,
    usage: ProviderUsage,
    input_price_per_million: float | None = None,
    output_price_per_million: float | None = None,
    program_id: str | None = None,
    finding_id: str | None = None,
) -> CostEntry:
    known_usage = usage.input_tokens is not None and usage.output_tokens is not None
    known_price = input_price_per_million is not None and output_price_per_million is not None
    estimated = None
    if known_usage and known_price:
        estimated = (usage.input_tokens * input_price_per_million + usage.output_tokens * output_price_per_million) / 1_000_000
    entry = CostEntry(
        provider=provider, model=model, task=task, program_id=program_id, finding_id=finding_id,
        input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
        input_price_per_million=input_price_per_million, output_price_per_million=output_price_per_million,
        estimated_cost=estimated, usage_status="KNOWN" if estimated is not None else "UNKNOWN",
    )
    return repository.add_cost(entry)
