"""Reading the rule catalogue and deciding which rules a tenant runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from ..domain.entities.audit import AuditAction
from ..domain.entities.rules import Rule, TenantRuleSettings, builtin_catalogue
from ..domain.errors import NotFoundError
from ..domain.permissions import Permission
from ..domain.ports import UnitOfWork
from .audit_recorder import AuditRecorder
from .context import Principal

#: The catalogue is compiled into the build, so its publication date is the build's, not a
#: runtime value. Fixed rather than ``now()`` so two calls a second apart do not report a
#: different catalogue.
_CATALOGUE_PUBLISHED_AT = datetime(2026, 7, 29, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class RuleView:
    """A rule as a tenant sees it: the definition plus their own decision about it."""

    rule: Rule
    enabled: bool
    disabled_reason: str = ""


class ListRules:
    """The catalogue, annotated with this tenant's opt-outs."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal) -> list[RuleView]:
        principal.require(Permission.POLICY_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            settings = await uow.rule_settings.get()
        catalogue = builtin_catalogue(_CATALOGUE_PUBLISHED_AT)
        return [
            RuleView(
                rule=rule,
                enabled=settings.is_enabled(rule.key),
                disabled_reason=settings.disabled.get(rule.key, ""),
            )
            # Worst first, and stable within a severity, so the list does not reshuffle
            # between requests.
            for rule in sorted(catalogue.rules, key=lambda r: (-r.severity.base_score, r.key))
        ]


class SetRuleEnabled:
    """Turn a rule on or off for one organization.

    Audited either way. Switching detection off is exactly the change somebody will want to
    explain — or account for — six months later, and it is also what an attacker with a
    stolen console session would do first.
    """

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, rule_key: str, enabled: bool, reason: str = ""
    ) -> RuleView:
        principal.require(Permission.POLICY_WRITE)
        catalogue = builtin_catalogue(_CATALOGUE_PUBLISHED_AT)
        rule = catalogue.rule(rule_key.strip().lower())
        if rule is None:
            # Refused rather than stored. Accepting an unknown key would let the settings row
            # accumulate opt-outs for rules that do not exist, which reads later as though
            # detection were disabled when it never was.
            raise NotFoundError(f"No rule named {rule_key!r}.")

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            settings: TenantRuleSettings = await uow.rule_settings.get()
            if enabled:
                settings.enable(rule.key)
            else:
                settings.disable(rule.key, reason=reason)
            await uow.rule_settings.save(settings)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.RULE_TOGGLED.value,
                resource_type="rule",
                resource_id=rule.key,
                metadata={
                    "enabled": enabled,
                    "reason": reason.strip()[:500],
                    "severity": rule.severity.value,
                },
            )
            await uow.commit()
            return RuleView(
                rule=rule,
                enabled=settings.is_enabled(rule.key),
                disabled_reason=settings.disabled.get(rule.key, ""),
            )
