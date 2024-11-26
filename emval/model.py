from typing import Any


class ValidatedEmail:
    """
    Represents a validated email address with various components and normalized forms.

    Attributes:
        original (str): The email address provided to validate_email. If passed as bytes, it will be converted to a string.
        normalized (str): The normalized email address should be used instead of the original. It converts IDNA ASCII domain names to Unicode and normalizes both the local part and domain. The normalized address combines the local part and domain name with an '@' sign.
        local_part (str): The local part of the email address (the part before the '@' sign) after it has been Unicode normalized.
        domain_name (str): The domain part of the email address (the part after the '@' sign) after Unicode normalization.
        domain_address (Optional[str]): If the domain part is a domain literal, it will be an IPv4Address or IPv6Address object.
        is_deliverable (bool): Whether the email address is deliverable.

    Methods:
        __repr__() -> str:
            Returns a string representation of the ValidatedEmail instance, displaying all its attributes.

        __eq__(other: Any) -> bool:
            Compares two ValidatedEmail instances for equality.

        as_dict() -> Dict[str, Any]:
            Returns a dictionary representation of the ValidatedEmail instance. If the domain_address is present, it is converted to a string.
    """

    def __init__(
        self,
        original: str,
        normalized: str,
        local_part: str,
        domain_name: str,
        domain_address: str | None = None,
        is_deliverable: bool = True,
    ):
        self.original = original
        self.normalized = normalized
        self.local_part = local_part
        self.domain_name = domain_name
        self.domain_address = domain_address
        self.is_deliverable = is_deliverable

    def __repr__(self) -> str:
        return (
            f"ValidatedEmail(original={self.original}, normalized={self.normalized}, "
            f"local_part={self.local_part}, domain_name={self.domain_name}, domain_address={self.domain_address}, is_deliverable={self.is_deliverable})"
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ValidatedEmail):
            return (
                self.original == other.original
                and self.normalized == other.normalized
                and self.local_part == other.local_part
                and self.domain_name == other.domain_name
                and self.domain_address == other.domain_address
                and self.is_deliverable == other.is_deliverable
            )
        return False

    def as_dict(self) -> dict[str, Any]:
        d = self.__dict__
        if d.get("domain_address"):
            d["domain_address"] = repr(d["domain_address"])
        return d
