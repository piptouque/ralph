"""Tests for the api.auth.scim module."""

import pytest
import responses
from pydantic import TypeAdapter

from ralph.api.auth.oidc import UserAccessibleAuthority
from ralph.api.auth.scim import (
    get_scim_resource_types,
    post_scim_resource_search,
)
from ralph.conf import ClientAccessScimSettings

from tests.fixtures.auth import (
    SCIM_CLIENT_ACCESS_CLIENT_CAN_EDIT_JQ_PATH,
    SCIM_CLIENT_ACCESS_CLIENT_ID_JQ_PATH,
    SCIM_CLIENT_ACCESS_SCIM_BASE_URL,
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
    post_scim_resource_search.cache_clear()

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

    assert response.json()["accessible_clients"] == []
    assert "target" not in response.json()


@pytest.mark.anyio
@responses.activate
async def test_api_auth_oidc_scim_get_whoami_valid_clients(client, monkeypatch):
    """Test API with an invalid provider discovery."""

    configure_env_for_mock_oidc_auth(monkeypatch)
    configure_env_for_mock_scim_client_access(monkeypatch)

    # Clear LRU cache
    get_scim_resource_types.cache_clear()
    post_scim_resource_search.cache_clear()

    user_sub = "a_user"
    oidc_token = mock_oidc_user(sub=user_sub)

    user_client_data = [
        {"client_id": "test_client_1", "name": "Test Client 1", "can_edit": False},
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

    assert response.json()["accessible_clients"] == [
        {
            "agent": {
                "openid": "https://iss.example.com/application/test_client_1",
                "objectType": "Agent",
                "name": "Test Client 1",
            },
            "can_edit": False,
        },
        {
            "agent": {
                "openid": "https://iss.example.com/application/test_client_2",
                "objectType": "Agent",
                "name": None,
            },
            "can_edit": False,
        },
    ]
    assert TypeAdapter(list[UserAccessibleAuthority]).validate_python(
        response.json()["accessible_clients"]
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
    post_scim_resource_search.cache_clear()

    user_sub = "a_user"
    oidc_token = mock_oidc_user(sub=user_sub)

    group_name = "a_group"
    client_data = [
        {"client_id": "test_client_1", "name": "Test Client 1", "can_edit": False}
    ]
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

    assert response.json()["accessible_clients"] == [
        {
            "agent": {
                "openid": "https://iss.example.com/application/test_client_1",
                "objectType": "Agent",
                "name": "Test Client 1",
            },
            "can_edit": False,
        },
        {
            "agent": {
                "openid": "https://iss.example.com/application/test_client_3",
                "objectType": "Agent",
                "name": None,
            },
            "can_edit": False,
        },
    ]
    assert TypeAdapter(list[UserAccessibleAuthority]).validate_python(
        response.json()["accessible_clients"]
    )
    assert "target" not in response.json()


@pytest.mark.anyio
@responses.activate
async def test_api_auth_oidc_scim_get_whoami_invalid_config(client, monkeypatch):
    """Test API with an invalid SCIM config.

    Should not make the request fail. Only `accessible_clients` should return None
    """

    configure_env_for_mock_oidc_auth(monkeypatch)
    configure_env_for_mock_scim_client_access(monkeypatch)

    # Clear LRU cache
    get_scim_resource_types.cache_clear()
    post_scim_resource_search.cache_clear()

    invalid_scim_config = ClientAccessScimSettings(
        scim_base_url=SCIM_CLIENT_ACCESS_SCIM_BASE_URL,
        user_extension_schema=SCIM_CLIENT_ACCESS_USER_EXTENSION_SCHEMA,
        client_can_edit_jq_path=SCIM_CLIENT_ACCESS_CLIENT_CAN_EDIT_JQ_PATH,
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

    assert response.json()["accessible_clients"] is None
    assert "target" not in response.json()
