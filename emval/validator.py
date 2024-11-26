from typing import Union

from emval import _emval

from .model import ValidatedEmail


class EmailValidator:
    """
    Initializes an EmailValidator object.


    Args:
        email (Union[str, bytes]): The email address to validate.
        allow_smtputf8 (bool): Whether to allow SMTPUTF8. Default is True.
        allow_empty_local (bool): Whether to allow empty local part. \
        Default is False.
        allow_quoted_local (bool): Whether to allow quoted local part. \
        Default is False.
        allow_domain_literal (bool): Whether to allow domain literals. \
        Default is False.
        deliverable_address (bool): Whether to check if the email address is \
        deliverable. Default is True.

    """

    def __init__(
        self,
        allow_smtputf8: bool = True,
        allow_empty_local: bool = False,
        allow_quoted_local: bool = False,
        allow_domain_literal: bool = False,
        deliverable_address: bool = True,
    ):
        self._emval = _emval.EmailValidator(
            allow_smtputf8,
            allow_empty_local,
            allow_quoted_local,
            allow_domain_literal,
            deliverable_address,
        )

    def validate_email(self, email: Union[str, bytes]) -> ValidatedEmail:
        """
        Validates an email address.

        Args:
            email: The email address to validate.

        Returns:
            A ValidatedEmail instance if the email is valid.
        """
        validated_email = self._emval.validate_email(email)
        return ValidatedEmail(
            original=validated_email.original,
            normalized=validated_email.normalized,
            local_part=validated_email.local_part,
            domain_name=validated_email.domain_name,
            domain_address=validated_email.domain_address,
            is_deliverable=validated_email.is_deliverable,
        )


def validate_email(
    email: Union[str, bytes],
    allow_smtputf8: bool = True,
    allow_empty_local: bool = False,
    allow_quoted_local: bool = False,
    allow_domain_literal: bool = False,
    deliverable_address: bool = True,
) -> ValidatedEmail:
    """
    Validates an email address with optional parameters.

    Args:
        email (Union[str, bytes]): The email address to validate.
        allow_smtputf8 (bool): Whether to allow SMTPUTF8. Default is True.
        allow_empty_local (bool): Whether to allow empty local part. \
        Default is False.
        allow_quoted_local (bool): Whether to allow quoted local part. \
        Default is False.
        allow_domain_literal (bool): Whether to allow domain literals. \
        Default is False.
        deliverable_address (bool): Whether to check if the email address is \
        deliverable. Default is True.

    Returns:
        ValidatedEmail: An instance if the email is valid.
    """
    emval = EmailValidator(
        allow_smtputf8,
        allow_empty_local,
        allow_quoted_local,
        allow_domain_literal,
        deliverable_address,
    )
    return emval.validate_email(email)
