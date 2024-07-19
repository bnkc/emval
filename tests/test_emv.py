import pytest
from emv import EmailValidator


def test_validate_email():
    validate = EmailValidator(allow_domain_literal=True)
    assert validate.email("example@domain.com")
    with pytest.raises(Exception):
        validate.email("plainaddress")


# def test_domain_literal() -> None:
# validate = EmailValidator(allow_domain_literal=true)

# Check parsing IPv4 addresses.
# validated = validate.email("me@[127.0.0.1]")
# assert validated.domain == "[127.0.0.1]"
# assert repr(validated.domain_address) == "IPv4Address('127.0.0.1')"

# # Check parsing IPv6 addresses.
# validated = validate_email("me@[IPv6:::1]", allow_domain_literal=True)
# assert validated.domain == "[IPv6:::1]"
# assert repr(validated.domain_address) == "IPv6Address('::1')"

# # Check that IPv6 addresses are normalized.
# validated = validate_email(
#     "me@[IPv6:0000:0000:0000:0000:0000:0000:0000:0001]", allow_domain_literal=True
# )
# assert validated.domain == "[IPv6:::1]"
# assert repr(validated.domain_address) == "IPv6Address('::1')"
