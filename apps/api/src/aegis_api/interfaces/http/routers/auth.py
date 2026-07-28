"""Authentication routes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from ....application.auth import (
    AuthenticateUser,
    ChangePassword,
    CompleteMfaChallenge,
    DescribeCurrentPrincipal,
    RefreshSession,
    RegisterOrganization,
    RevokeSession,
)
from ....application.mfa import ConfirmMfa, DisableMfa, EnrolMfa
from ..dependencies import (
    REFRESH_COOKIE_NAME,
    ContainerDep,
    ContextDep,
    SettingsDep,
    UserPrincipalDep,
    read_refresh_token,
)
from ..schemas import (
    ChangePasswordRequest,
    CurrentPrincipalResponse,
    LoginRequest,
    LogoutResponse,
    MfaChallengeResponse,
    MfaConfirmRequest,
    MfaDisableRequest,
    MfaEnrolRequest,
    MfaEnrolResponse,
    MfaVerifyRequest,
    OrganizationResponse,
    RefreshRequest,
    RegisterRequest,
    RegistrationResponse,
    TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_refresh_cookie(response: Response, token: str, max_age: int, *, secure: bool) -> None:
    """Deliver the refresh token as a restricted cookie.

    ``HttpOnly`` keeps it out of reach of JavaScript (threat T-12), ``SameSite=Strict``
    plus the narrow path largely removes CSRF exposure on the one endpoint that accepts it.
    """
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/api/v1/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE_NAME, path="/api/v1/auth")


@router.post(
    "/register",
    response_model=RegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization and its first Owner",
)
async def register(
    payload: RegisterRequest,
    container: ContainerDep,
    settings: SettingsDep,
    context: ContextDep,
    response: Response,
) -> RegistrationResponse:
    result = await RegisterOrganization(
        container.unit_of_work(),
        container.auth,
        allow_signup=settings.allow_self_service_signup,
    ).execute(
        organization_name=payload.organization_name,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        context=context,
    )
    _set_refresh_cookie(
        response,
        result.tokens.refresh_token,
        settings.refresh_token_ttl_seconds,
        secure=settings.environment.is_production_like,
    )
    return RegistrationResponse(
        organization=OrganizationResponse.of(result.organization),
        user_id=result.user_id,
        email=result.email,
        tokens=TokenResponse.of(result.tokens, include_refresh=False),
    )


@router.post(
    "/login",
    response_model=TokenResponse | MfaChallengeResponse,
    summary="Exchange credentials for tokens, or receive an MFA challenge",
)
async def login(
    payload: LoginRequest,
    container: ContainerDep,
    settings: SettingsDep,
    context: ContextDep,
    response: Response,
) -> TokenResponse | MfaChallengeResponse:
    result = await AuthenticateUser(container.unit_of_work(), container.auth).execute(
        email=payload.email,
        password=payload.password,
        organization_slug=payload.organization_slug,
        context=context,
    )
    if result.challenge is not None:
        return MfaChallengeResponse(
            challenge_token=result.challenge.challenge_token,
            expires_at=result.challenge.expires_at,
            methods=result.challenge.methods,
        )
    assert result.tokens is not None
    _set_refresh_cookie(
        response,
        result.tokens.refresh_token,
        settings.refresh_token_ttl_seconds,
        secure=settings.environment.is_production_like,
    )
    return TokenResponse.of(result.tokens, include_refresh=False)


@router.post("/mfa/verify", response_model=TokenResponse, summary="Complete an MFA challenge")
async def verify_mfa(
    payload: MfaVerifyRequest,
    container: ContainerDep,
    settings: SettingsDep,
    context: ContextDep,
    response: Response,
) -> TokenResponse:
    tokens = await CompleteMfaChallenge(container.unit_of_work(), container.auth).execute(
        challenge_token=payload.challenge_token, code=payload.code, context=context
    )
    _set_refresh_cookie(
        response,
        tokens.refresh_token,
        settings.refresh_token_ttl_seconds,
        secure=settings.environment.is_production_like,
    )
    return TokenResponse.of(tokens, include_refresh=False)


@router.post("/refresh", response_model=TokenResponse, summary="Rotate the refresh token")
async def refresh(
    payload: RefreshRequest,
    request: Request,
    container: ContainerDep,
    settings: SettingsDep,
    context: ContextDep,
    response: Response,
) -> TokenResponse:
    token = read_refresh_token(request, payload.refresh_token)
    tokens = await RefreshSession(container.unit_of_work(), container.auth).execute(
        refresh_token=token, context=context
    )
    if tokens.refresh_token:
        _set_refresh_cookie(
            response,
            tokens.refresh_token,
            settings.refresh_token_ttl_seconds,
            secure=settings.environment.is_production_like,
        )
    # The plaintext refresh token is never echoed in a JSON body when cookie delivery is in
    # use; a client that reads it from the body would defeat HttpOnly.
    return TokenResponse.of(tokens, include_refresh=False)


@router.post("/logout", response_model=LogoutResponse, summary="Revoke the current session")
async def logout(
    principal: UserPrincipalDep, container: ContainerDep, response: Response
) -> LogoutResponse:
    revoked = await RevokeSession(container.unit_of_work(), container.auth).execute(
        principal=principal, all_sessions=False
    )
    _clear_refresh_cookie(response)
    return LogoutResponse(sessions_revoked=revoked)


@router.post(
    "/logout-all", response_model=LogoutResponse, summary="Revoke every session for this user"
)
async def logout_all(
    principal: UserPrincipalDep, container: ContainerDep, response: Response
) -> LogoutResponse:
    revoked = await RevokeSession(container.unit_of_work(), container.auth).execute(
        principal=principal, all_sessions=True
    )
    _clear_refresh_cookie(response)
    return LogoutResponse(sessions_revoked=revoked)


@router.post(
    "/password/change", response_model=LogoutResponse, summary="Change the current password"
)
async def change_password(
    payload: ChangePasswordRequest, principal: UserPrincipalDep, container: ContainerDep
) -> LogoutResponse:
    revoked = await ChangePassword(container.unit_of_work(), container.auth).execute(
        principal=principal,
        current_password=payload.current_password,
        new_password=payload.new_password,
    )
    return LogoutResponse(sessions_revoked=revoked)


@router.get("/me", response_model=CurrentPrincipalResponse, summary="The current principal")
async def me(principal: UserPrincipalDep, container: ContainerDep) -> CurrentPrincipalResponse:
    result = await DescribeCurrentPrincipal(container.unit_of_work()).execute(principal=principal)
    return CurrentPrincipalResponse.of(result)


@router.post(
    "/mfa/enroll",
    response_model=MfaEnrolResponse,
    summary="Begin TOTP enrolment — secret and recovery codes are shown once",
)
async def enrol_mfa(
    payload: MfaEnrolRequest,
    principal: UserPrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
) -> MfaEnrolResponse:
    result = await EnrolMfa(
        container.unit_of_work(),
        container.auth,
        container.auth.cipher,
        settings.mfa_policy,
        issuer=settings.mfa_issuer,
    ).execute(principal=principal, password=payload.password)
    return MfaEnrolResponse(
        secret=result.secret,
        provisioning_uri=result.provisioning_uri,
        recovery_codes=result.recovery_codes,
    )


@router.post(
    "/mfa/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Confirm enrolment with a live code",
)
async def confirm_mfa(
    payload: MfaConfirmRequest, principal: UserPrincipalDep, container: ContainerDep
) -> None:
    await ConfirmMfa(container.unit_of_work(), container.auth, container.auth.cipher).execute(
        principal=principal, code=payload.code
    )


@router.post(
    "/mfa/disable",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable multi-factor authentication",
)
async def disable_mfa(
    payload: MfaDisableRequest,
    principal: UserPrincipalDep,
    container: ContainerDep,
    settings: SettingsDep,
) -> None:
    await DisableMfa(container.unit_of_work(), container.auth, settings.mfa_policy).execute(
        principal=principal, password=payload.password
    )
