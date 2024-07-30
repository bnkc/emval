# This is the public API of emv
from .validator import validate_email, EmailValidator
from .model import ValidatedEmail, ValidatedDomain
from .error import EmvSyntaxError, EmvDomainLiteralError, EmvLengthError

__all__ = [
    "validate_email",
    "EmailValidator",
    "ValidatedEmail",
    "ValidatedDomain",
    "EmvSyntaxError",
    "EmvDomainLiteralError",
    "EmvLengthError",
]
