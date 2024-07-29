from typing import Any
import pytest
from emv._emv import EmailValidator, SyntaxError, ValidatedEmail


# def test_validate_email():
#     validate = EmailValidator()
#     assert validate.email("example@domain.com")
#     with pytest.raises(Exception):
#         validate.email("plainaddress")


# def MakeValidatedEmail(**kwargs: Any) -> ValidatedEmail:
#     ret = ValidatedEmail
#     for k, v in kwargs.items():
#         setattr(ret, k, v)
#     return ret
#

# @pytest.mark.parametrize(
#     "email_input,output",
#     [
#         # (
#         #     "Abc@example.tld",
#         #     MakeValidatedEmail(
#         #         local_part="Abc",
#         #         ascii_local_part="Abc",
#         #         smtputf8=False,
#         #         ascii_domain="example.tld",
#         #         domain="example.tld",
#         #         normalized="Abc@example.tld",
#         #         ascii_email="Abc@example.tld",
#         #     ),
#         # ),
#         # (
#         #     "Abc.123@test-example.com",
#         #     MakeValidatedEmail(
#         #         local_part="Abc.123",
#         #         ascii_local_part="Abc.123",
#         #         smtputf8=False,
#         #         ascii_domain="test-example.com",
#         #         domain="test-example.com",
#         #         normalized="Abc.123@test-example.com",
#         #         ascii_email="Abc.123@test-example.com",
#         #     ),
#         # ),
#         # (
#         #     "user+mailbox/department=shipping@example.tld",
#         #     MakeValidatedEmail(
#         #         local_part="user+mailbox/department=shipping",
#         #         ascii_local_part="user+mailbox/department=shipping",
#         #         smtputf8=False,
#         #         ascii_domain="example.tld",
#         #         domain="example.tld",
#         #         normalized="user+mailbox/department=shipping@example.tld",
#         #         ascii_email="user+mailbox/department=shipping@example.tld",
#         #     ),
#         # ),
#         # (
#         #     "!#$%&'*+-/=?^_`.{|}~@example.tld",
#         #     MakeValidatedEmail(
#         #         local_part="!#$%&'*+-/=?^_`.{|}~",
#         #         ascii_local_part="!#$%&'*+-/=?^_`.{|}~",
#         #         smtputf8=False,
#         #         ascii_domain="example.tld",
#         #         domain="example.tld",
#         #         normalized="!#$%&'*+-/=?^_`.{|}~@example.tld",
#         #         ascii_email="!#$%&'*+-/=?^_`.{|}~@example.tld",
#         #     ),
#         # ),
#         # (
#         #     "jeff@臺網中心.tw",
#         #     MakeValidatedEmail(
#         #         local_part="jeff",
#         #         ascii_local_part="jeff",
#         #         smtputf8=False,
#         #         ascii_domain="xn--fiqq24b10vi0d.tw",
#         #         domain="臺網中心.tw",
#         #         normalized="jeff@臺網中心.tw",
#         #         ascii_email="jeff@xn--fiqq24b10vi0d.tw",
#         #     ),
#         # ),
#         # (
#         #     '"quoted local part"@example.org',
#         #     MakeValidatedEmail(
#         #         local_part='"quoted local part"',
#         #         ascii_local_part='"quoted local part"',
#         #         smtputf8=False,
#         #         ascii_domain="example.org",
#         #         domain="example.org",
#         #         normalized='"quoted local part"@example.org',
#         #         ascii_email='"quoted local part"@example.org',
#         #     ),
#         # ),
#         # (
#         #     '"de-quoted.local.part"@example.org',
#         #     MakeValidatedEmail(
#         #         local_part="de-quoted.local.part",
#         #         ascii_local_part="de-quoted.local.part",
#         #         smtputf8=False,
#         #         ascii_domain="example.org",
#         #         domain="example.org",
#         #         normalized="de-quoted.local.part@example.org",
#         #         ascii_email="de-quoted.local.part@example.org",
#         #     ),
#         # ),
#         # (
#         #     "MyName <me@example.org>",
#         #     MakeValidatedEmail(
#         #         local_part="me",
#         #         ascii_local_part="me",
#         #         smtputf8=False,
#         #         ascii_domain="example.org",
#         #         domain="example.org",
#         #         normalized="me@example.org",
#         #         ascii_email="me@example.org",
#         #         display_name="MyName",
#         #     ),
#         # ),
#         # (
#         #     "My Name <me@example.org>",
#         #     MakeValidatedEmail(
#         #         local_part="me",
#         #         ascii_local_part="me",
#         #         smtputf8=False,
#         #         ascii_domain="example.org",
#         #         domain="example.org",
#         #         normalized="me@example.org",
#         #         ascii_email="me@example.org",
#         #         display_name="My Name",
#         #     ),
#         # ),
#         (
#             r'"My.\"Na\\me\".Is" <"me \" \\ me"@example.org>',
#             MakeValidatedEmail(
#                 local_part=r'"me \" \\ me"',
#                 ascii_local_part=r'"me \" \\ me"',
#                 smtputf8=False,
#                 ascii_domain="example.org",
#                 domain="example.org",
#                 normalized=r'"me \" \\ me"@example.org',
#                 ascii_email=r'"me \" \\ me"@example.org',
#                 display_name='My."Na\\me".Is',
#             ),
#         ),
#     ],
# )
# def test_email_valid(email_input: str, output: ValidatedEmail) -> None:
#     # These addresses do not require SMTPUTF8. See test_email_valid_intl_local_part
#     # for addresses that are valid but require SMTPUTF8. Check that it passes with
#     # allow_smtput8 both on and off.
#     emv = EmailValidator(
#         email_input,
#         check_deliverability=False,
#         allow_smtputf8=False,
#         allow_quoted_local=True,
#         allow_display_name=True,
#     )
#
#     assert emv.validate_email(email_input) == output
#     # assert (
#     #     validate_email(
#     #         email_input,
#     #         check_deliverability=False,
#     #         allow_smtputf8=True,
#     #         allow_quoted_local=True,
#     #         allow_display_name=True,
#     #     )
#     #     == output
#     # )
#
#     # Check that the old `email` attribute to access the normalized form still works
#     # if the DeprecationWarning is suppressed.
#     import warnings
#
#     with warnings.catch_warnings():
#         warnings.filterwarnings("ignore", category=DeprecationWarning)
#         assert emailinfo.email == emailinfo.normalized
#


def test_domain_literal() -> None:
    emv = EmailValidator(allow_domain_literal=True)
    # Check parsing IPv4 addresses.
    validated_email = emv.validate_email("me@[127.0.0.1]")
    assert validated_email.domain.name == "[127.0.0.1]"

    assert repr(validated_email.domain.address) == "IPv4Address('127.0.0.1')"

    # Check parsing IPv6 addresses.
    validated_email = emv.validate_email("me@[IPv6:::1]")
    assert validated_email.domain.name == "[IPv6:::1]"
    assert repr(validated_email.domain.address) == "IPv6Address('::1')"

    # # Check that IPv6 addresses are normalized.
    validated_email = emv.validate_email(
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
        emv.validate_email(email_input)
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
        emv.validate_email(email_input)

    assert (
        str(exc_info.value) == "Quoting the part before the @-sign is not allowed here."
    )

    # But they are valid if quoting is allowed.
    emv = EmailValidator(allow_quoted_local=True)
    validated_email = emv.validate_email(email_input)

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
        emv.validate_email(email_input)
    assert str(exc_info.value) == expected_error


def test_email_empty_local() -> None:
    emv = EmailValidator(allow_empty_local=True)
    emv.validate_email("@example.com")

    emv = EmailValidator(allow_empty_local=True, allow_quoted_local=True)
    emv.validate_email('""@example.com')


def test_case_insensitive_mailbox_name() -> None:
    emv = EmailValidator()

    assert (
        emv.validate_email("POSTMASTER@example.com").normalized
        == "postmaster@example.com"
    )
    assert (
        emv.validate_email("NOT-POSTMASTER@example.com").normalized
        == "NOT-POSTMASTER@example.com"
    )
