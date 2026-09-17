"""SCIM client tool for the Ralph API."""

import logging
from threading import Lock
from typing import Dict, Optional

import jq
import requests
from cachetools import TTLCache, cached
from fastapi import HTTPException, status
from pydantic import AnyUrl, BaseModel, ValidationError

from ralph.conf import ClientAccessScimSettings, settings

# API auth logger
logger = logging.getLogger(__name__)


class ClientData(BaseModel):
    """Client data fetched from SCIM 'Client Access' Extension."""

    client_id: str
    name: Optional[str]


@cached(
    cache=TTLCache(maxsize=settings.AUTH_CACHE_MAX_SIZE, ttl=60),
    lock=Lock(),
)
def get_scim_resource_types(
    scim_resource_types_endpoint: AnyUrl, auth_header: str
) -> Dict:
    """Fetch SCIM `/ResourceTypes` from given endpoint."""
    try:
        response = requests.get(
            f"{scim_resource_types_endpoint}",
            headers={"Authorization": auth_header},
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()
        return {item["id"]: item for item in data["Resources"]}
    except requests.exceptions.RequestException as exc:
        logger.error("Unable to get SCIM ResourceTypes endpoint: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@cached(
    cache=TTLCache(maxsize=settings.AUTH_CACHE_MAX_SIZE, ttl=60),
    lock=Lock(),
)
def get_scim_resource(url: AnyUrl, auth_header: str) -> Dict:
    """Get SCIM resource from given endpoint with `resource_id`."""
    try:
        response = requests.get(
            f"{url}",
            headers={"Authorization": auth_header},
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()
        return data
    except requests.exceptions.RequestException as exc:
        logger.error("Unable to get SCIM Resource endpoint: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_user_accessible_clients(
    user_sub: str,
    client_access_config: ClientAccessScimSettings,
    auth_header: str,
) -> list[ClientData]:
    """Get the the ids of OIDC clients that are 'owned' by the authenticated user.

    An authenticated user also 'owns' any clients 'owned'
    by a group they are a member of.

    Args:
        user_sub (str): user's OIDC sub (identifier)
        client_access_config (ClientAccessScimSettings): SCIM 'Client Access'
                                                      user extension settings
        auth_header (str): OIDC authentication header value.
                           Must be authorized to access SCIM resources.

    Return:
        client_ids (list[str])

    Raises:
        HTTPException
    """
    resource_types = get_scim_resource_types(
        client_access_config.resource_types_endpoint, auth_header=auth_header
    )
    user_resource_type = resource_types["User"]

    user_endpoint = user_resource_type["endpoint"]

    scim_user = get_scim_resource(
        url=f"{user_endpoint}/{user_sub}", auth_header=auth_header
    )
    if client_access_config.user_extension_schema not in scim_user:
        logger.error(
            "Unable to get provided schema %s from SCIM user",
            client_access_config.user_extension_schema,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    def get_client_ids(data: dict) -> list[str]:
        return (
            jq.compile(client_access_config.client_id_jq_path).input_value(data).all()
        )

    def get_client_names(data: dict, client_ids: list[str]) -> list[Optional[str]]:
        if client_access_config.client_name_jq_path:
            return (
                jq.compile(client_access_config.client_name_jq_path)
                .input_value(data)
                .all()
            )
        else:
            return [None] * len(client_ids)

    data = scim_user[client_access_config.user_extension_schema]
    client_ids = None
    try:
        client_ids = get_client_ids(data)
    except ValueError:
        logger.error(
            "Input data did not adhere to `client_id` jq schema `%s`",
            client_access_config.client_id_jq_path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    client_names = None
    try:
        client_names = get_client_names(data, client_ids=client_ids)
    except ValueError:
        logger.warning(
            "Input data did not adhere to `client_name` jq schema `%s`",
            client_access_config.client_name_jq_path,
        )
        client_names = [None] * len(client_ids)

    try:
        client_data = [
            ClientData(client_id=client_id, name=client_name if client_name else None)
            for client_id, client_name in zip(client_ids, client_names)
        ]
        return client_data
    except ValidationError as e:
        logger.error(
            "Client data validation failed",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
