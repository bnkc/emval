from typing import Union
from .model import ValidatedEmail, ValidatedDomain
from .error import EmvSyntaxError, EmvDomainLiteralError, EmvLengthError
from emv import _emv


EXCEPTIONS = {
    _emv.SyntaxError: EmvSyntaxError,
    _emv.DomainLiteralError: EmvDomainLiteralError,
    _emv.LengthError: EmvLengthError,
}


class EmailValidator:
    def __init__(
        self,
        allow_smtputf8: bool = True,
        allow_empty_local: bool = False,
        allow_quoted_local: bool = False,
        allow_domain_literal: bool = False,
    ):
        """
        Initializes an EmailValidator object.

        Args:
            allow_smtputf8: Whether to allow SMTPUTF8.
            allow_empty_local: Whether to allow empty local part.
            allow_quoted_local: Whether to allow quoted local part.
            allow_domain_literal: Whether to allow domain literals.
        """
        self._validator = _emv.EmailValidator(
            allow_smtputf8,
            allow_empty_local,
            allow_quoted_local,
            allow_domain_literal,
        )

    def validate_email(self, email: Union[str, bytes]) -> ValidatedEmail:
        """
        Validates an email address.

        Args:
            email: The email address to validate.

        Returns:
            A ValidatedEmail instance if the email is valid.

        Raises:
            SyntaxError: If the email syntax is invalid.
            DomainLiteralError: If domain literals are not allowed.
            LengthError: If the email length exceeds the maximum allowed length.
        """
        try:
            validated_email = self._validator.validate_email(email)
            domain = ValidatedDomain(
                address=validated_email.domain.address,
                name=validated_email.domain.name,
            )
            return ValidatedEmail(
                original=validated_email.original,
                normalized=validated_email.normalized,
                local_part=validated_email.local_part,
                domain=domain,
            )
        except Exception as e:
            raise EXCEPTIONS[type(e)](str(e))


def validate_email(
    email: Union[str, bytes],
    allow_smtputf8: bool = True,
    allow_empty_local: bool = False,
    allow_quoted_local: bool = False,
    allow_domain_literal: bool = False,
) -> ValidatedEmail:
    """
    Validates an email address with optional parameters.

    Args:
        email: The email address to validate.
        allow_smtputf8: Whether to allow SMTPUTF8.
        allow_empty_local: Whether to allow empty local part.
        allow_quoted_local: Whether to allow quoted local part.
        allow_domain_literal: Whether to allow domain literals.

    Returns:
        A ValidatedEmail instance if the email is valid.

    Raises:
        SyntaxError: If the email syntax is invalid.
        DomainLiteralError: If domain literals are not allowed.
        LengthError: If the email length exceeds the maximum allowed length.
    """
    validator = EmailValidator(
        allow_smtputf8,
        allow_empty_local,
        allow_quoted_local,
        allow_domain_literal,
    )
    return validator.validate_email(email)
