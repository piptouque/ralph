"""SCIM client tool for the Ralph API."""

import logging
from threading import Lock
from typing import Dict, Optional
from urllib.parse import urlparse

import jq
import requests
from cachetools import TTLCache, cached
from fastapi import HTTPException, status
from pydantic import AnyUrl, BaseModel, HttpUrl, ValidationError

from ralph.conf import ClientAccessScimSettings, settings

# API auth logger
logger = logging.getLogger(__name__)

DEFAULT_CAN_EDIT = False


class ScimClientUserData(BaseModel):
    """Client data fetched from SCIM 'Client Access' Extension."""

    client_id: str
    can_edit: bool
    name: Optional[str] = None


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
def post_scim_resource_search(
    resource_endpoint: AnyUrl, search_filter: str, auth_header: str
) -> Dict:
    """POST an SCIM resource search from given endpoint filter."""
    try:
        response = requests.post(
            f"{resource_endpoint}/.search",
            headers={"Authorization": auth_header},
            json={"filter": search_filter},
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
) -> list[ScimClientUserData]:
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
    resource_types_endpoint = HttpUrl(
        f"{client_access_config.scim_base_url}/ResourceTypes"
    )
    resource_types = get_scim_resource_types(
        resource_types_endpoint, auth_header=auth_header
    )
    user_resource_type = resource_types["User"]

    user_endpoint = user_resource_type["endpoint"]
    parsed_user_endpoint = urlparse(user_endpoint)
    if not parsed_user_endpoint.netloc:
        # if the user endpoint is relative,
        # add the SCIM base url
        user_endpoint = HttpUrl(f"{client_access_config.scim_base_url}/{user_endpoint}")
    search_filter = f'userName eq "{user_sub}"'

    scim_user_search = post_scim_resource_search(
        resource_endpoint=user_endpoint,
        search_filter=search_filter,
        auth_header=auth_header,
    )
    if not len(scim_user_search["Resources"]) == 1:
        logger.error("Unable to find SCIM Resource user: %s", user_sub)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scim_user = scim_user_search["Resources"][0]

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

    def get_client_can_edit_flags(data: dict) -> list[str]:
        if not client_access_config.client_can_edit_jq_path:
            return [None] * len(client_ids)
        return (
            jq.compile(client_access_config.client_can_edit_jq_path)
            .input_value(data)
            .all()
        )

    def get_client_names(data: dict, client_ids: list[str]) -> list[Optional[str]]:
        if not client_access_config.client_name_jq_path:
            return [None] * len(client_ids)
        return (
            jq.compile(client_access_config.client_name_jq_path).input_value(data).all()
        )

    data = scim_user[client_access_config.user_extension_schema]
    client_ids = None
    try:
        client_ids = get_client_ids(data)
    except ValueError:
        logger.exception(
            "Input data did not adhere to `client_id` jq schema `%s`",
            client_access_config.client_id_jq_path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    try:
        client_can_edit_flags = get_client_can_edit_flags(data)
    except ValueError:
        logger.warning(
            "Input data did not adhere to `client_can_edit` jq schema `%s`",
            client_access_config.client_can_edit_jq_path,
            stacklevel=logging.WARNING,
        )
        client_can_edit_flags = [None] * len(client_ids)

    client_names = None
    try:
        client_names = get_client_names(data, client_ids=client_ids)
    except ValueError:
        logger.exception(
            "Input data did not adhere to `client_name` jq schema `%s`",
            client_access_config.client_name_jq_path,
            stacklevel=logging.WARNING,
        )
        client_names = [None] * len(client_ids)

    try:
        client_data = [
            ScimClientUserData(
                client_id=client_id,
                name=client_name,
                can_edit=can_edit if can_edit is not None else False,
            )
            for client_id, can_edit, client_name in zip(
                client_ids, client_can_edit_flags, client_names
            )
        ]
        return client_data
    except ValidationError as e:
        logger.exception(
            "Client data validation failed",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
