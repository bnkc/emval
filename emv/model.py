from typing import Optional


class ValidatedDomain:
    def __init__(self, address: Optional[str], name: str):
        """
        Represents a validated domain.

        Args:
            address: The IP address of the domain, if available.
            name: The normalized domain name.
        """
        self.address = address
        self.name = name

    def __repr__(self) -> str:
        return f"ValidatedDomain(address={self.address}, name={self.name})"


class ValidatedEmail:
    def __init__(
        self, original: str, normalized: str, local_part: str, domain: ValidatedDomain
    ):
        """
        Represents a validated email.

        Args:
            original: The original email address.
            normalized: The normalized email address.
            local_part: The local part of the email.
            domain: The validated domain part of the email.
        """
        self.original = original
        self.normalized = normalized
        self.local_part = local_part
        self.domain = domain

    def __repr__(self) -> str:
        return (
            f"ValidatedEmail(original={self.original}, normalized={self.normalized}, "
            f"local_part={self.local_part}, domain={self.domain})"
        )
