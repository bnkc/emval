from emv import _emv


class EmvSyntaxError(_emv.SyntaxError):
    """
    Raised when there is a syntax error in the email address.
    """

    pass


class EmvDomainLiteralError(_emv.DomainLiteralError):
    """
    Raised when domain literals are not allowed but encountered.
    """

    pass


class EmvLengthError(_emv.LengthError):
    """
    Raised when the email length exceeds the maximum allowed length.
    """

    pass
