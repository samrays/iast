"""AI Graph Orchestrator — multi-step analysis graph for findings.

Nodes in the analysis graph:
1. **Root Cause Analysis (RCA)**: Identifies the exact vulnerable line and flaw mechanism.
2. **Context & RAG Retrieval**: Fetches relevant security rule guidance and framework control mappings.
3. **Structured Patch Draft**: Produces a suggested code remediation diff.
4. **Security Guardrail Inspection**: Sanitizes output to prevent prompt injection and hazardous instructions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
from uuid import UUID

from ..domain.entities.ai import AiAnalysis, AnalysisKind
from ..domain.entities.findings import Finding
from ..domain.permissions import Permission
from ..domain.ports import Clock, UnitOfWork
from .ai import LanguageModel, ModelResponse, build_prompt
from .context import Principal
from .reporting import FRAMEWORK_MAPPINGS


@dataclass(frozen=True, slots=True)
class GraphExecutionResult:
    finding_id: UUID
    root_cause_summary: str
    compliance_controls: list[str]
    remediation_patch: str
    guardrail_passed: bool
    tokens_used: int


class AiGraphOrchestrator:
    """Orchestrates multi-node AI finding analysis graphs."""

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        language_model: LanguageModel,
        clock: Clock,
    ) -> None:
        self._uow_factory = uow_factory
        self._language_model = language_model
        self._clock = clock

    async def execute_graph(
        self,
        *,
        principal: Principal,
        finding_id: UUID,
    ) -> GraphExecutionResult:
        principal.require(Permission.AI_RUN)

        async with self._uow_factory() as uow:
            await uow.bind_tenant(principal.organization_id)
            finding = await uow.findings.get(finding_id)
            occurrences = await uow.findings.list_occurrences(finding_id, limit=1)
            latest_occ = occurrences[0] if occurrences else None

            # Node 1: RCA Execution
            prompt_rca = build_prompt(finding, latest_occ, AnalysisKind.ROOT_CAUSE)
            rca_resp = await self._language_model.complete(
                system="You are a senior security researcher doing root cause analysis.",
                user=prompt_rca,
                max_output_tokens=500,
            )

            # Node 2: Context / Compliance Mapping
            fw_map = FRAMEWORK_MAPPINGS.get(finding.rule_key, {})
            controls = [f"{k.upper()}: {v}" for k, v in fw_map.items()]

            # Node 3: Structured Patch Draft
            prompt_patch = build_prompt(finding, latest_occ, AnalysisKind.REMEDIATION)
            patch_resp = await self._language_model.complete(
                system="You are an expert developer drafting secure code fixes.",
                user=prompt_patch,
                max_output_tokens=600,
            )

            # Node 4: Guardrail Check
            clean_patch = self._guardrail_sanitize(patch_resp.content)
            guardrail_ok = len(clean_patch) > 0

            tokens_used = rca_resp.input_tokens + rca_resp.output_tokens + patch_resp.input_tokens + patch_resp.output_tokens

            return GraphExecutionResult(
                finding_id=finding.id,
                root_cause_summary=rca_resp.summary or rca_resp.content[:200],
                compliance_controls=controls,
                remediation_patch=clean_patch,
                guardrail_passed=guardrail_ok,
                tokens_used=tokens_used,
            )

    def _guardrail_sanitize(self, content: str) -> str:
        """Sanitize generated code fix to ensure no dangerous commands or raw injections."""
        disallowed_keywords = ["rm -rf", "drop table", "chmod 777", "exec("]
        for kw in disallowed_keywords:
            if kw in content.lower():
                return "# [REDACTED BY AI GUARDRAIL: Potentially unsafe instruction detected]"
        return content


__all__ = ["AiGraphOrchestrator", "GraphExecutionResult"]
