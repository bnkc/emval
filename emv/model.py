from typing import Optional, Dict, Any


class ValidatedEmail:
    """
    Represents a validated email address with various components and normalized forms.

    Attributes:
        original (str): The email address provided to validate_email. If passed as bytes, it will be converted to a string.
        normalized (str): The normalized email address should be used instead of the original. It converts IDNA ASCII domain names to Unicode and normalizes both the local part and domain. The normalized address combines the local part and domain name with an '@' sign.
        local_part (str): The local part of the email address (the part before the '@' sign) after it has been Unicode normalized.
        domain_name (str): The domain part of the email address (the part after the '@' sign) after Unicode normalization.
        domain_address (Optional[str]): If the domain part is a domain literal, it will be an IPv4Address or IPv6Address object.

    Methods:
        __repr__() -> str:
            Returns a string representation of the ValidatedEmail instance, displaying all its attributes.

        as_dict() -> Dict[str, Any]:
            Returns a dictionary representation of the ValidatedEmail instance. If the domain_address is present, it is converted to a string.
    """

    def __init__(
        self,
        original: str,
        normalized: str,
        local_part: str,
        domain_name: str,
        domain_address: Optional[str] = None,
    ):
        self.original = original
        self.normalized = normalized
        self.local_part = local_part
        self.domain_name = domain_name
        self.domain_address = domain_address

    def __repr__(self) -> str:
        return (
            f"ValidatedEmail(original={self.original}, normalized={self.normalized}, "
            f"local_part={self.local_part}, domain_name={self.domain_name}, domain_address={self.domain_address})"
        )

    def as_dict(self) -> Dict[str, Any]:
        d = self.__dict__
        if d.get("domain_address"):
            d["domain_address"] = repr(d["domain_address"])
        return d

    def __eq__(self, other) -> bool:
        if isinstance(other, ValidatedEmail):
            return (
                self.original == other.original
                and self.normalized == other.normalized
                and self.local_part == other.local_part
                and self.domain_name == other.domain_name
                and self.domain_address == other.domain_address
            )
        return False
