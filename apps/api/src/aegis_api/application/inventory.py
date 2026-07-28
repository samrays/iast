"""Application inventory: applications and their deployment environments."""

from __future__ import annotations

from uuid import UUID

from ..domain.entities import (
    Application,
    ApplicationEnvironment,
    Criticality,
    EnvironmentKind,
    Language,
    ProtectionMode,
)
from ..domain.entities.audit import AuditAction
from ..domain.errors import (
    ConflictError,
    FeatureNotLicensedError,
    NotFoundError,
    ValidationError,
)
from ..domain.permissions import Permission
from ..domain.policies import InventoryPolicy
from ..domain.ports import Clock, UnitOfWork
from ..domain.value_objects import Slug
from .audit_recorder import AuditRecorder
from .context import Principal
from .dto import ApplicationSummary, EnvironmentSummary, Page


def _environment_summary(environment: ApplicationEnvironment) -> EnvironmentSummary:
    return EnvironmentSummary(
        id=environment.id,
        application_id=environment.application_id,
        kind=environment.kind.value,
        internet_facing=environment.internet_facing,
        protection_mode=environment.protection_mode.value,
        created_at=environment.created_at,
    )


def _application_summary(
    application: Application, environments: list[ApplicationEnvironment]
) -> ApplicationSummary:
    return ApplicationSummary(
        id=application.id,
        name=application.name,
        slug=application.slug.value,
        language=application.language.value,
        criticality=application.criticality.value,
        tags=list(application.tags),
        repository_url=application.repository_url,
        description=application.description,
        created_at=application.created_at,
        environments=[_environment_summary(e) for e in environments],
    )


class ListApplications:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        limit: int,
        cursor: str | None,
        search: str | None = None,
        tags: list[str] | None = None,
    ) -> Page[ApplicationSummary]:
        principal.require(Permission.APP_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            applications, next_cursor = await uow.applications.list_all(
                limit=limit, cursor=cursor, search=search, tags=tags
            )
            items = [
                _application_summary(app, await uow.environments.list_for_application(app.id))
                for app in applications
            ]
            return Page(items=items, next_cursor=next_cursor, limit=limit)


class GetApplication:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal, application_id: UUID) -> ApplicationSummary:
        principal.require(Permission.APP_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            application = await uow.applications.get(application_id)
            if application is None:
                # 404 rather than 403 for a resource in another tenant — confirming
                # existence would itself be a disclosure (ADR-0003).
                raise NotFoundError("Application", application_id)
            environments = await uow.environments.list_for_application(application.id)
            return _application_summary(application, environments)


class CreateApplication:
    def __init__(self, uow: UnitOfWork, clock: Clock, policy: InventoryPolicy) -> None:
        self._uow = uow
        self._clock = clock
        self._policy = policy

    async def execute(
        self,
        *,
        principal: Principal,
        name: str,
        language: Language,
        criticality: Criticality,
        tags: list[str],
        repository_url: str | None,
        description: str,
        environments: list[tuple[EnvironmentKind, bool]] | None = None,
    ) -> ApplicationSummary:
        principal.require(Permission.APP_WRITE)

        try:
            normalized_tags = self._policy.normalize_tags(tags)
        except ValueError as exc:
            raise ValidationError(str(exc), field="tags") from exc

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)

            license_ = await uow.licenses.get_for_organization(principal.organization_id)
            if license_ is not None:
                license_.check_applications(await uow.applications.count())

            slug = Slug.from_name(name)
            if await uow.applications.get_by_slug(slug) is not None:
                raise ConflictError(f"An application with the slug {slug.value!r} already exists.")

            application = Application(
                organization_id=principal.organization_id,
                name=name,
                slug=slug,
                language=language,
                criticality=criticality,
                tags=tuple(normalized_tags),
                repository_url=(repository_url or "").strip() or None,
                description=description,
            )
            await uow.applications.add(application)

            created: list[ApplicationEnvironment] = []
            for kind, internet_facing in environments or [(EnvironmentKind.PRODUCTION, False)]:
                environment = ApplicationEnvironment(
                    organization_id=principal.organization_id,
                    application_id=application.id,
                    kind=kind,
                    internet_facing=internet_facing,
                )
                await uow.environments.add(environment)
                created.append(environment)

            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.APPLICATION_CREATED.value,
                resource_type="application",
                resource_id=application.id,
                metadata={
                    "name": application.name,
                    "language": language.value,
                    "criticality": criticality.value,
                    "environments": [e.kind.value for e in created],
                },
            )
            await uow.commit()
            return _application_summary(application, created)


class UpdateApplication:
    def __init__(self, uow: UnitOfWork, policy: InventoryPolicy) -> None:
        self._uow = uow
        self._policy = policy

    async def execute(
        self,
        *,
        principal: Principal,
        application_id: UUID,
        name: str | None,
        criticality: Criticality | None,
        tags: list[str] | None,
        repository_url: str | None,
        description: str | None,
    ) -> ApplicationSummary:
        principal.require(Permission.APP_WRITE)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            application = await uow.applications.get(application_id)
            if application is None:
                raise NotFoundError("Application", application_id)

            try:
                application.update(
                    name=name,
                    criticality=criticality,
                    tags=tags,
                    repository_url=repository_url,
                    description=description,
                    policy=self._policy,
                )
            except ValueError as exc:
                raise ValidationError(str(exc), field="tags") from exc

            await uow.applications.update(application)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.APPLICATION_UPDATED.value,
                resource_type="application",
                resource_id=application.id,
                metadata={"name": application.name, "criticality": application.criticality.value},
            )
            await uow.commit()
            environments = await uow.environments.list_for_application(application.id)
            return _application_summary(application, environments)


class DeleteApplication:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, *, principal: Principal, application_id: UUID) -> None:
        principal.require(Permission.APP_DELETE)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            application = await uow.applications.get(application_id)
            if application is None:
                raise NotFoundError("Application", application_id)

            await uow.applications.delete(application_id)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.APPLICATION_DELETED.value,
                resource_type="application",
                resource_id=application_id,
                metadata={"name": application.name, "slug": application.slug.value},
            )
            await uow.commit()


class ListEnvironments:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self, *, principal: Principal, application_id: UUID
    ) -> list[EnvironmentSummary]:
        principal.require(Permission.APP_READ)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            if await uow.applications.get(application_id) is None:
                raise NotFoundError("Application", application_id)
            environments = await uow.environments.list_for_application(application_id)
            return [_environment_summary(e) for e in environments]


class CreateEnvironment:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(
        self,
        *,
        principal: Principal,
        application_id: UUID,
        kind: EnvironmentKind,
        internet_facing: bool,
    ) -> EnvironmentSummary:
        principal.require(Permission.APP_WRITE)
        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            if await uow.applications.get(application_id) is None:
                raise NotFoundError("Application", application_id)
            if await uow.environments.find(application_id, kind.value) is not None:
                raise ConflictError(
                    f"A {kind.value} environment already exists for this application."
                )

            environment = ApplicationEnvironment(
                organization_id=principal.organization_id,
                application_id=application_id,
                kind=kind,
                internet_facing=internet_facing,
            )
            await uow.environments.add(environment)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.ENVIRONMENT_CREATED.value,
                resource_type="environment",
                resource_id=environment.id,
                metadata={"application_id": str(application_id), "kind": kind.value},
            )
            await uow.commit()
            return _environment_summary(environment)


class SetProtectionMode:
    """Change the ADR mode for an environment.

    The soak requirement enforced by the entity means production cannot jump straight to
    blocking — see docs/02-threat-model.md §4.3.
    """

    def __init__(self, uow: UnitOfWork, clock: Clock) -> None:
        self._uow = uow
        self._clock = clock

    async def execute(
        self, *, principal: Principal, environment_id: UUID, mode: ProtectionMode
    ) -> EnvironmentSummary:
        principal.require(Permission.POLICY_WRITE)
        now = self._clock.now()

        async with self._uow as uow:
            await uow.bind_tenant(principal.organization_id)
            environment = await uow.environments.get(environment_id)
            if environment is None:
                raise NotFoundError("Environment", environment_id)

            license_ = await uow.licenses.get_for_organization(principal.organization_id)
            if (
                mode is ProtectionMode.BLOCK
                and license_ is not None
                and not license_.protection_enabled
            ):
                raise FeatureNotLicensedError("Application Detection & Response blocking")

            previous = environment.protection_mode
            environment.set_protection_mode(mode, now)
            await uow.environments.update(environment)
            await AuditRecorder(uow.audit).record(
                principal=principal,
                action=AuditAction.PROTECTION_MODE_CHANGED.value,
                resource_type="environment",
                resource_id=environment.id,
                metadata={"from": previous.value, "to": mode.value},
            )
            await uow.commit()
            return _environment_summary(environment)
