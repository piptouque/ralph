"""SCIM client tool for the Ralph API."""

import logging
from functools import lru_cache
from typing import Dict

import jq
import requests
from fastapi import HTTPException, status
from pydantic import AnyUrl

from ralph.conf import ClientOwnershipScimSettings

# API auth logger
logger = logging.getLogger(__name__)


@lru_cache()
def get_scim_resource_types(
    scim_resource_types_endpoint: AnyUrl, access_token: str
) -> Dict:
    """Fetch SCIM `/ResourceTypes` from given endpoint."""
    try:
        response = requests.get(
            f"{scim_resource_types_endpoint}",
            headers={"Authorization": f"Bearer {access_token}"},
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


@lru_cache()
def get_scim_resource(endpoint: AnyUrl, id: str, access_token: str) -> Dict:
    """Get SCIM resource from given endpoint with `resource_id`."""
    try:
        response = requests.get(
            f"{endpoint}/{id}",
            headers={"Authorization": f"Bearer {access_token}"},
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


def get_user_owned_client_ids(
    user_sub: str,
    client_ownership_config: ClientOwnershipScimSettings,
    access_token: str,
) -> list[str]:
    """Get the the ids of OIDC clients that are 'owned' by the authenticated user.

    An authenticated user also 'owns' any clients 'owned'
    by a group they are a member of.

    Args:
        user_sub (str): user's OIDC sub (identifier)
        client_ownership_config (ClientOwnershipScimSettings): SCIM 'Client ownership'
                                                      user extension settings
        access_token (str): OIDC authentication token

    Return:
        client_ids (list[str])

    Raises:
        HTTPException
    """
    resource_types = get_scim_resource_types(
        client_ownership_config.resource_types_endpoint, access_token=access_token
    )
    user_resource_type = resource_types["User"]
    group_resource_type = resource_types["Group"]

    user_endpoint = user_resource_type["endpoint"]
    group_endpoint = group_resource_type["endpoint"]

    scim_user = get_scim_resource(
        endpoint=user_endpoint, id=user_sub, access_token=access_token
    )
    if client_ownership_config.user_extension_schema not in scim_user:
        logger.error(
            "Unable to get provided schema %s from SCIM user",
            client_ownership_config.user_extension_schema,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    def get_client_ids(client_data: dict) -> str:
        try:
            return (
                jq.compile(client_ownership_config.extension_schema_jq_path)
                .input_value(client_data)
                .all()
            )
        except ValueError:
            logger.error(
                "Input data did not adhere to jq schema `%s`",
                client_ownership_config.extension_schema_jq_path,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None

    client_data = scim_user[client_ownership_config.user_extension_schema]
    client_ids = get_client_ids(client_data)

    scim_group_ids = [group["value"] for group in scim_user["groups"]]

    for scim_group_id in scim_group_ids:
        scim_group = get_scim_resource(
            endpoint=group_endpoint, id=scim_group_id, access_token=access_token
        )
        if client_ownership_config.group_extension_schema not in scim_group:
            logger.error(
                "Unable to get provided schema %s from SCIM group",
                client_ownership_config.group_extension_schema,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        client_data = scim_group[client_ownership_config.group_extension_schema]
        client_ids += get_client_ids(client_data)
    return client_ids
