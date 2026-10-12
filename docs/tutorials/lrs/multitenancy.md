
# Multitenancy

By default, all authenticated users have full read and write access to the server. Ralph LRS implements the specified [Authority mechanism](https://github.com/adlnet/xAPI-Spec/blob/master/xAPI-Data.md#249-authority) to restrict behavior.

## Filtering results by authority (multitenancy)

In Ralph LRS, all incoming statements are assigned an `authority` (or ownership) derived from the user that makes the request. You may restrict read access to users "own" statements (thus enabling multitenancy) by setting the following environment variable:

```bash title=".env"
RALPH_LRS_RESTRICT_BY_AUTHORITY=True # Default: False
```

!!! warning
    Two accounts with different credentials may share the same `authority`, meaning they can access the same statements. It is the administrator's responsibility to ensure that `authority` is properly assigned.

!!! info
    If not using "scopes", or for users with limited "scopes", using this option will make the use of option `?mine=True` implicit when fetching statement.

### Extending Authority filtering to include 'Client Access' (OIDC only)

!!! info
    Requires an OpenID Identity Provider as means of authentication with:
    - Ralph configured as an OIDC client (`CLIENT_ID` and `CLIENT_SECRET` set)
    - a 'Client Access' concept defined for users,
    - an SCIM server interface that can provision users,
    - a custom SCIM User Extension that includes this 'Client Access' data

You may extend the filtering to include any `authority` that is recognised by the SCIM server as 'accessible' to the current user.
In the case of Ralph, the `authority` of other OIDC clients that the user has access to.
The concept of 'accessibility' of another OIDC client is not defined here,
it is up to the IdP/SCIM server.


You must then define the following environment variables:

```bash title=".env"
RALPH_RUNSERVER_SCIM_CLIENT_ACCESS__resource_types_endpoint = "https://my_scim_server/scim/v2/ResourceTypes"
RALPH_RUNSERVER_SCIM_CLIENT_ACCESS__user_extension_schema  = "urn:ietf:params:scim:schemas:extension:client_access:2.0:User"
RALPH_RUNSERVER_SCIM_CLIENT_ACCESS__client_id_jq_path = ".clients.[].value"
```


- `resource_types_endpoint` is the HTTPS address of the `/ResourceTypes` SCIM endpoint.
- `client_id_jq_path` is a [jq](https://jqlang.org/) path to a list of OIDC client ids
   inside the 'Client Access' extension part of the SCIM `/User` response.

And also optionally:

```bash title=".env"
RALPH_RUNSERVER_SCIM_CLIENT_ACCESS__client_name_jq_path = ".clients.[].display"
```

For instance, if by querying your SCIM server at `https://my_scimerver/scim/v2/Users/USER_ID` response:

```json
{
      "active": true,
      "emails": [
        ...
      ],
      "groups": [
        ...
      ],
      "id": "b0cf1068-e7b1-1040-9f72-11ae0b538ed0",
      "meta": {
        ...
      },
      "name": {
        ...
      },
      "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:ietf:params:scim:schemas:extension:client_access:2.0:User",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
      ],
      "urn:ietf:params:scim:schemas:extension:client_access:2.0:User": {
        "clients": [
            {
                "value": CLIENT_ID_1,
                "display": CLIENT_NAME_1
            },
            {
                "value": CLIENT_ID_2,
                "display": CLIENT_NAME_2
            }
        ]
      },
      "userName": USER_ID
}
```

Then:

- the 'Client Access' extension URI is `"urn:ietf:params:scim:schemas:extension:client_access:2.0:User"`
- the correct `jq` path to get `[CLIENT_ID_1, CLIENT_ID_2]` would be `".clients.[].value"`.
- the correct `jq` path to get `[CLIENT_NAME_1, CLIENT_NAME_2]` would be `".clients.[].display"`.

If all the above is, you may enable that behaviour with this flag:

```bash title=".env"
RALPH_LRS_EXTEND_AUTHORITY_TO_CLIENT_ACCESS=True # Default: False
```

### Scopes

In Ralph, users are assigned scopes which may be used to restrict endpoint access or
functionalities. You may enable this option by setting the following environment variable:

```bash title=".env"
RALPH_LRS_RESTRICT_BY_SCOPES=True # Default: False
```

Valid scopes are a slight variation on those proposed by the
[xAPI specification](https://github.com/adlnet/xAPI-Spec/blob/master/xAPI-Communication.md#details-15):

- statements/write
- statements/read/mine
- statements/read
- state/write
- state/read
- define
- profile/write
- profile/read
- authority/write
- all/read
- all
