"""Tests for the api.auth.scim module."""

import pytest
import responses
from pydantic import TypeAdapter

from ralph.api.auth.scim import (
    get_scim_resource,
    get_scim_resource_types,
)
from ralph.conf import ClientAccessScimSettings
from ralph.models.xapi.base.agents import BaseXapiAgentWithOpenId

from tests.fixtures.auth import (
    SCIM_CLIENT_ACCESS_CLIENT_ID_JQ_PATH,
    SCIM_CLIENT_ACCESS_RESOURCE_TYPES_ENDPOINT,
    SCIM_CLIENT_ACCESS_USER_EXTENSION_SCHEMA,
    mock_oidc_user,
    mock_scim_server,
)
from tests.helpers import (
    configure_env_for_mock_oidc_auth,
    configure_env_for_mock_scim_client_access,
)


@pytest.mark.anyio
@responses.activate
async def test_api_auth_oidc_scim_get_whoami_valid_no_clients(client, monkeypatch):
    """Test API with an invalid provider discovery."""

    configure_env_for_mock_oidc_auth(monkeypatch)
    configure_env_for_mock_scim_client_access(monkeypatch)

    # Clear LRU cache
    get_scim_resource_types.cache_clear()
    get_scim_resource.cache_clear()

    user_sub = "a_user"
    oidc_token = mock_oidc_user(sub=user_sub)

    mock_scim_server(user_sub=user_sub, access_token=oidc_token)

    headers = {"Authorization": f"Bearer {oidc_token}"}
    response = await client.get(
        "/whoami",
        headers=headers,
    )
    assert response.status_code == 200
    assert len(response.json().keys()) == 3

    assert response.json()["client_agents"] == []
    assert "target" not in response.json()


@pytest.mark.anyio
@responses.activate
async def test_api_auth_oidc_scim_get_whoami_valid_clients(client, monkeypatch):
    """Test API with an invalid provider discovery."""

    configure_env_for_mock_oidc_auth(monkeypatch)
    configure_env_for_mock_scim_client_access(monkeypatch)

    # Clear LRU cache
    get_scim_resource_types.cache_clear()
    get_scim_resource.cache_clear()

    user_sub = "a_user"
    oidc_token = mock_oidc_user(sub=user_sub)

    user_client_data = [
        {"client_id": "test_client_1", "name": "Test Client 1"},
        {"client_id": "test_client_2"},
    ]
    mock_scim_server(
        user_sub=user_sub, user_client_data=user_client_data, access_token=oidc_token
    )

    headers = {"Authorization": f"Bearer {oidc_token}"}
    response = await client.get(
        "/whoami",
        headers=headers,
    )
    assert response.status_code == 200
    assert len(response.json().keys()) == 3

    assert response.json()["client_agents"] == [
        {
            "openid": "https://iss.example.com/application/test_client_1",
            "objectType": "Agent",
            "name": "Test Client 1",
        },
        {
            "openid": "https://iss.example.com/application/test_client_2",
            "objectType": "Agent",
            "name": None,
        },
    ]
    assert TypeAdapter(list[BaseXapiAgentWithOpenId]).validate_python(
        response.json()["client_agents"]
    )
    assert "target" not in response.json()


@pytest.mark.anyio
@responses.activate
async def test_api_auth_oidc_scim_get_whoami_valid_group_clients(client, monkeypatch):
    """Test API with an invalid provider discovery."""

    configure_env_for_mock_oidc_auth(monkeypatch)
    configure_env_for_mock_scim_client_access(monkeypatch)

    # Clear LRU cache
    get_scim_resource_types.cache_clear()
    get_scim_resource.cache_clear()

    user_sub = "a_user"
    oidc_token = mock_oidc_user(sub=user_sub)

    group_name = "a_group"
    client_data = [{"client_id": "test_client_1", "name": "Test Client 1"}]
    group_client_data = [{"client_id": "test_client_3"}]

    mock_scim_server(
        access_token=oidc_token,
        user_sub=user_sub,
        group_name=group_name,
        user_client_data=client_data,
        group_client_data=group_client_data,
    )

    headers = {"Authorization": f"Bearer {oidc_token}"}
    response = await client.get(
        "/whoami",
        headers=headers,
    )
    assert response.status_code == 200
    assert len(response.json().keys()) == 3

    assert response.json()["client_agents"] == [
        {
            "openid": "https://iss.example.com/application/test_client_1",
            "objectType": "Agent",
            "name": "Test Client 1",
        },
        {
            "openid": "https://iss.example.com/application/test_client_3",
            "objectType": "Agent",
            "name": None,
        },
    ]
    assert TypeAdapter(list[BaseXapiAgentWithOpenId]).validate_python(
        response.json()["client_agents"]
    )
    assert "target" not in response.json()


@pytest.mark.anyio
@responses.activate
async def test_api_auth_oidc_scim_get_whoami_invalid_config(client, monkeypatch):
    """Test API with an invalid SCIM config.

    Should not make the request fail. Only `client_agents` should return None
    """

    configure_env_for_mock_oidc_auth(monkeypatch)
    configure_env_for_mock_scim_client_access(monkeypatch)

    # Clear LRU cache
    get_scim_resource_types.cache_clear()
    get_scim_resource.cache_clear()

    invalid_scim_config = ClientAccessScimSettings(
        resource_types_endpoint=SCIM_CLIENT_ACCESS_RESOURCE_TYPES_ENDPOINT,
        user_extension_schema=SCIM_CLIENT_ACCESS_USER_EXTENSION_SCHEMA,
        client_id_jq_path=SCIM_CLIENT_ACCESS_CLIENT_ID_JQ_PATH + ".nope",
    )
    monkeypatch.setattr(
        "ralph.api.auth.settings.RUNSERVER_SCIM_CLIENT_ACCESS", invalid_scim_config
    )

    user_sub = "a_user"
    oidc_token = mock_oidc_user(sub=user_sub)

    client_data = [{"client_id": "test_client_1"}]

    mock_scim_server(
        access_token=oidc_token,
        user_sub=user_sub,
        user_client_data=client_data,
    )

    headers = {"Authorization": f"Bearer {oidc_token}"}
    response = await client.get(
        "/whoami",
        headers=headers,
    )
    assert response.status_code == 200
    assert len(response.json().keys()) == 3

    assert response.json()["client_agents"] is None
    assert "target" not in response.json()
