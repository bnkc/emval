# This is the public API of emval
from .validator import validate_email, EmailValidator
from .model import ValidatedEmail

__all__ = [
    "validate_email",
    "EmailValidator",
    "ValidatedEmail",
]
