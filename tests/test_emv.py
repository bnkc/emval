import pytest
from emv import EmailValidator, SyntaxError


def test_validate_email():
    validate = EmailValidator()
    assert validate.email("example@domain.com")
    with pytest.raises(Exception):
        validate.email("plainaddress")


def test_domain_literal() -> None:
    validate = EmailValidator(allow_domain_literal=True)
    # Check parsing IPv4 addresses.
    validated_email = validate.email("me@[127.0.0.1]")
    assert validated_email.domain.domain == "[127.0.0.1]"

    assert repr(validated_email.domain.address) == "IPv4Address('127.0.0.1')"

    # Check parsing IPv6 addresses.
    # validated = validate.email("me@[IPv6:::1]")
    # assert validated.domain == "[IPv6:::1]"
    # # assert repr(validated.domain_address) == "IPv6Address('::1')"

    # # Check that IPv6 addresses are normalized.
    # validated = validate.email(
    #     "me@[IPv6:0000:0000:0000:0000:0000:0000:0000:0001]", allow_domain_literal=True
    # )
    # assert validated.domain == "[IPv6:::1]"
    # assert repr(validated.domain_address) == "IPv6Address('::1')"

    # @pytest.mark.parametrize(
    #     "email_input,normalized_local_part",
    #     [
    #         ('"quoted.with..unicode.λ"@example.com', '"quoted.with..unicode.λ"'),
    #     ],
    # )
    # def test_email_valid_only_if_quoted_local_part(
    #     email_input: str, normalized_local_part: str
    # ) -> None:
    #     validate = EmailValidator()
    #
    # These addresses are invalid with the default allow_quoted_local=False option.
    # with pytest.raises(SyntaxError) as exc_info:
    #     validate.email(email_input)
    # assert (
    #     str(exc_info.value) == "Quoting the part before the @-sign is not allowed here."
    # )

    # But they are valid if quoting is allowed.
    # validate = EmailValidator(allow_quoted_local=True)
    # validated = validate.email(email_input)

    # Check that the normalized form correctly removed unnecessary backslash escaping
    # and even the quoting if they weren't necessary.
    # assert validated.local_part == normalized_local_part
