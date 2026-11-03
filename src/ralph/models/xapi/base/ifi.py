"""Base xAPI `Inverse Functional Identifier` definitions."""

from typing import Union, get_args

from pydantic import StringConstraints
from typing_extensions import Annotated

from ralph.conf import NonEmptyStrictStr

from ..config import BaseModelWithConfig
from .common import IRI, MailtoEmail


class BaseXapiAccount(BaseModelWithConfig):
    """Pydantic model for IFI `account` property.

    Attributes:
        homePage (IRI): Consists of the home page of the account's service provider.
        name (str): Consists of the unique id or name of the Actor's account.
    """

    homePage: IRI
    name: NonEmptyStrictStr


class BaseXapiMboxIFI(BaseModelWithConfig):
    """Pydantic model for mailto Inverse Functional Identifier.

    Attributes:
        mbox (MailtoEmail): Consists of the Agent's email address.
    """

    mbox: MailtoEmail


class BaseXapiMboxSha1SumIFI(BaseModelWithConfig):
    """Pydantic model for hash Inverse Functional Identifier.

    Attributes:
        mbox_sha1sum (str): Consists of the SHA1 hash of the Agent's email address.
    """

    mbox_sha1sum: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]


class BaseXapiOpenIdIFI(BaseModelWithConfig):
    """Pydantic model for OpenID Inverse Functional Identifier.

    Attributes:
        openid (URI): Consists of an openID that uniquely identifies the Agent.
    """

    openid: str


class BaseXapiAccountIFI(BaseModelWithConfig):
    """Pydantic model for account Inverse Functional Identifier.

    Attributes:
        account (dict): See BaseXapiAccount.
    """

    account: BaseXapiAccount


BaseXapiIFI = Union[
    BaseXapiMboxIFI,
    BaseXapiMboxSha1SumIFI,
    BaseXapiOpenIdIFI,
    BaseXapiAccountIFI,
]


def is_same_ifi(ifi: BaseXapiIFI, other_ifi: BaseXapiIFI) -> bool:
    """Checks whether the two IFIs represent the same entity."""
    for ifi_type in get_args(BaseXapiIFI):
        if isinstance(ifi, ifi_type) and not isinstance(other_ifi, ifi_type):
            return False
    if isinstance(ifi, BaseXapiMboxIFI):
        return ifi.mbox == other_ifi.mbox
    if isinstance(ifi, BaseXapiMboxSha1SumIFI):
        return ifi.mbox_sha1sum == other_ifi.mbox_sha1sum
    if isinstance(ifi, BaseXapiOpenIdIFI):
        return ifi.openid == other_ifi.openid
    if isinstance(ifi, BaseXapiAccountIFI):
        return ifi.account == other_ifi.account
