# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Background S2S token acquisition for Agent 365 observability export."""

import asyncio
import logging
from datetime import timedelta

import httpx
import msal
from azure.identity.aio import ManagedIdentityCredential

from observability import token_cache

logger = logging.getLogger(__name__)

FMI_SCOPE = "api://AzureADTokenExchange/.default"
OBSERVABILITY_SCOPES = ["api://9b975845-388f-4429-889e-eab1ef63949c/.default"]
REFRESH_INTERVAL_SECONDS = 50 * 60


async def acquire_initial_token(
    tenant_id: str,
    agent_id: str,
    blueprint_client_id: str,
    blueprint_client_secret: str,
    use_managed_identity: bool,
) -> None:
    await _acquire_and_cache_token(
        tenant_id=tenant_id,
        agent_id=agent_id,
        blueprint_client_id=blueprint_client_id,
        blueprint_client_secret=blueprint_client_secret,
        use_managed_identity=use_managed_identity,
    )


async def run_token_service(
    tenant_id: str,
    agent_id: str,
    blueprint_client_id: str,
    blueprint_client_secret: str,
    use_managed_identity: bool,
) -> None:
    while True:
        try:
            await _acquire_and_cache_token(
                tenant_id=tenant_id,
                agent_id=agent_id,
                blueprint_client_id=blueprint_client_id,
                blueprint_client_secret=blueprint_client_secret,
                use_managed_identity=use_managed_identity,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning(
                "Failed to refresh observability S2S token; retrying in %d seconds.",
                REFRESH_INTERVAL_SECONDS,
                exc_info=True,
            )

        await asyncio.sleep(REFRESH_INTERVAL_SECONDS)


async def _acquire_and_cache_token(
    tenant_id: str,
    agent_id: str,
    blueprint_client_id: str,
    blueprint_client_secret: str,
    use_managed_identity: bool,
) -> None:
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    token_url = f"{authority}/oauth2/v2.0/token"

    if use_managed_identity:
        t1_token = await _acquire_t1_via_msi(
            token_url=token_url,
            blueprint_client_id=blueprint_client_id,
            agent_id=agent_id,
        )
    else:
        t1_token = await _acquire_t1_via_client_secret(
            token_url=token_url,
            blueprint_client_id=blueprint_client_id,
            blueprint_client_secret=blueprint_client_secret,
            agent_id=agent_id,
        )

    identity_app = msal.ConfidentialClientApplication(
        client_id=agent_id,
        authority=authority,
        client_credential={"client_assertion": t1_token},
    )
    observability_result = identity_app.acquire_token_for_client(
        scopes=OBSERVABILITY_SCOPES
    )

    token = _extract_access_token(observability_result, "observability token")
    expires_in = int(observability_result.get("expires_in", 3600))
    token_cache.cache_token(
        agent_id=agent_id,
        tenant_id=tenant_id,
        token=token,
        expires_in=timedelta(seconds=max(60, expires_in - 300)),
    )


async def _acquire_t1_via_msi(
    token_url: str,
    blueprint_client_id: str,
    agent_id: str,
) -> str:
    async with ManagedIdentityCredential() as credential:
        msi_token = await credential.get_token("api://AzureADTokenExchange")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": blueprint_client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": msi_token.token,
                "scope": FMI_SCOPE,
                "fmi_path": agent_id,
            },
        )

    result = _parse_response_json(response, "FMI T1 token (MSI)")
    return _extract_access_token(result, "FMI T1 token (MSI)")


async def _acquire_t1_via_client_secret(
    token_url: str,
    blueprint_client_id: str,
    blueprint_client_secret: str,
    agent_id: str,
) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": blueprint_client_id,
                "client_secret": blueprint_client_secret,
                "scope": FMI_SCOPE,
                "fmi_path": agent_id,
            },
        )

    result = _parse_response_json(response, "FMI T1 token (client secret)")
    return _extract_access_token(result, "FMI T1 token (client secret)")


def _parse_response_json(response: httpx.Response, token_label: str) -> dict:
    try:
        result = response.json()
    except ValueError as e:
        raise RuntimeError(
            f"Failed to parse {token_label} response: HTTP {response.status_code}"
        ) from e

    if response.status_code >= 400:
        raise RuntimeError(
            f"Failed to acquire {token_label}: "
            f"{result.get('error_description') or result.get('error') or result}"
        )

    return result


def _extract_access_token(result: dict, token_label: str) -> str:
    token = result.get("access_token")
    if token:
        return token

    raise RuntimeError(
        f"Failed to acquire {token_label}: "
        f"{result.get('error_description') or result.get('error') or result}"
    )

