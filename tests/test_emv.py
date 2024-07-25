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
    assert validated_email.domain.name == "[127.0.0.1]"

    assert repr(validated_email.domain.address) == "IPv4Address('127.0.0.1')"

    # Check parsing IPv6 addresses.
    validated_email = validate.email("me@[IPv6:::1]")
    assert validated_email.domain.name == "[IPv6:::1]"
    assert repr(validated_email.domain.address) == "IPv6Address('::1')"

    # # Check that IPv6 addresses are normalized.
    validated_email = validate.email(
        "me@[IPv6:0000:0000:0000:0000:0000:0000:0000:0001]"
    )
    assert validated_email.domain.name == "[IPv6:::1]"
    assert repr(validated_email.domain.address) == "IPv6Address('::1')"


@pytest.mark.parametrize(
    "email_input",
    [
        ("me@anything.arpa"),
        ("me@valid.invalid"),
        ("me@link.local"),
        ("me@host.localhost"),
        ("me@onion.onion.onion"),
        ("me@test.test.test"),
    ],
)
def test_email_invalid_reserved_domain(email_input: str) -> None:
    emv = EmailValidator()

    # Since these all fail deliverabiltiy from a static list,
    # DNS deliverability checks do not arise.
    with pytest.raises(SyntaxError) as exc_info:
        emv.email(email_input)
    assert "is a special-use or reserved name" in str(exc_info.value)


@pytest.mark.parametrize(
    "email_input,normalized_local_part",
    [
        (
            '"unnecessarily.quoted.local.part"@example.com',
            "unnecessarily.quoted.local.part",
        ),
        ('"quoted..local.part"@example.com', '"quoted..local.part"'),
        ('"quoted.with.at@"@example.com', '"quoted.with.at@"'),
        ('"quoted with space"@example.com', '"quoted with space"'),
        ('"quoted.with.dquote\\""@example.com', '"quoted.with.dquote\\""'),
        (
            '"unnecessarily.quoted.with.unicode.λ"@example.com',
            "unnecessarily.quoted.with.unicode.λ",
        ),
        ('"quoted.with..unicode.λ"@example.com', '"quoted.with..unicode.λ"'),
        (
            '"quoted.with.extraneous.\\escape"@example.com',
            "quoted.with.extraneous.escape",
        ),
    ],
)
def test_email_valid_only_if_quoted_local_part(
    email_input: str, normalized_local_part: str
) -> None:
    emv = EmailValidator()

    # These addresses are invalid with the default allow_quoted_local=False option.
    with pytest.raises(SyntaxError) as exc_info:
        emv.email(email_input)

    assert (
        str(exc_info.value) == "Quoting the part before the @-sign is not allowed here."
    )

    # But they are valid if quoting is allowed.
    emv = EmailValidator(allow_quoted_local=True)
    validated_email = emv.email(email_input)

    # Check that the normalized form correctly removed unnecessary backslash escaping
    # and even the quoting if they weren't necessary.
    assert validated_email.local_part == normalized_local_part


@pytest.mark.parametrize(
    ("email_input", "expected_error"),
    [
        (
            "λambdaツ@test",
            "Internationalized characters before the @-sign are not supported",
        ),
        (
            '"quoted.with..unicode.λ"@example.com',
            "Internationalized characters before the @-sign are not supported",
        ),
    ],
)
def test_email_invalid_character_smtputf8_off(
    email_input: str, expected_error: str
) -> None:
    emv = EmailValidator(allow_smtputf8=False, allow_quoted_local=True)

    # Check that internationalized characters are rejected if allow_smtputf8=False.
    with pytest.raises(SyntaxError) as exc_info:
        emv.email(email_input)
    assert str(exc_info.value) == expected_error


# def test_case_insensitive_mailbox_name() -> None:
#     emv = EmailValidator()
#
#     emv.email("POSTMASTER@test").normalized = "postmaster@test"
#     emv.email("NOT-POSTMASTER@test").normalized = "NOT-POSTMASTER@test"
