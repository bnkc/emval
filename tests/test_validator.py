from typing import Any
import pytest
from emv import validate_email


# This is the python-email-validator (https://github.com/JoshData/python-email-validator/blob/main/tests/test_syntax.py) test suite.


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
    # These addresses are invalid with the default allow_quoted_local=False option.
    with pytest.raises(SyntaxError) as exc_info:
        validate_email(email_input)

    assert (
        str(exc_info.value) == "Quoting the part before the @-sign is not allowed here."
    )

    # But they are valid if quoting is allowed.
    validated = validate_email(email_input, allow_quoted_local=True)

    # Check that the normalized form correctly removed unnecessary backslash escaping
    # and even the quoting if they weren't necessary.
    assert validated.local_part == normalized_local_part


def test_domain_literal() -> None:
    # Check parsing IPv4 addresses.
    validated = validate_email("me@[127.0.0.1]", allow_domain_literal=True)
    assert validated.domain.name == "[127.0.0.1]"
    assert repr(validated.domain.address) == "IPv4Address('127.0.0.1')"
    #
    # Check parsing IPv6 addresses.
    validated = validate_email("me@[IPv6:::1]", allow_domain_literal=True)
    assert validated.domain.name == "[IPv6:::1]"
    assert repr(validated.domain.address) == "IPv6Address('::1')"

    # Check that IPv6 addresses are normalized.
    validated = validate_email(
        "me@[IPv6:0000:0000:0000:0000:0000:0000:0000:0001]", allow_domain_literal=True
    )
    assert validated.domain.name == "[IPv6:::1]"
    assert repr(validated.domain.address) == "IPv6Address('::1')"


@pytest.mark.parametrize(
    "email_input,error_msg",
    [
        ("hello.world", "Invalid Email Address: Missing an '@' symbol."),
        (
            "my@localhost",
            "Invalid Domain: Must contain a period ('.') to be considered valid.",
        ),
        # (
        #     "my@.leadingdot.com",
        #     "An email address cannot have a period immediately after the @-sign.",
        # ),
        # (
        #     "my@．leadingfwdot.com",
        #     "An email address cannot have a period immediately after the @-sign.",
        # ),
        # ("my@twodots..com", "An email address cannot have two periods in a row."),
        # ("my@twofwdots．．.com", "An email address cannot have two periods in a row."),
        # ("my@trailingdot.com.", "An email address cannot end with a period."),
        # ("my@trailingfwdot.com．", "An email address cannot end with a period."),
        (
            "me@-leadingdash",
            "Invalid Domain: A hyphen ('-') cannot immediately follow the '@' symbol.",
        ),
        (
            "me@－leadingdashfw",
            "Invalid Domain: A hyphen ('-') cannot immediately follow the '@' symbol.",
        ),
        (
            "me@trailingdash-",
            "Invalid Domain: A hyphen ('-') cannot appear at the end of the domain.",
        ),
        (
            "me@trailingdashfw－",
            "Invalid Domain: A hyphen ('-') cannot appear at the end of the domain.",
        ),
        (
            "my@baddash.-.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the domain.",
        ),
        (
            "my@baddash.-a.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the domain.",
        ),
        (
            "my@baddash.b-.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the domain.",
        ),
        (
            "my@baddashfw.－.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the domain.",
        ),
        (
            "my@baddashfw.－a.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the domain.",
        ),
        (
            "my@baddashfw.b－.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the domain.",
        ),
        # (
        #     "my@example.com\n",
        #     "The part after the @-sign contains invalid characters: U+000A.",
        # ),
        # (
        #     "my@example\n.com",
        #     "The part after the @-sign contains invalid characters: U+000A.",
        # ),
        # ("me@x!", "The part after the @-sign contains invalid characters: '!'."),
        # ("me@x ", "The part after the @-sign contains invalid characters: SPACE."),
        # (".leadingdot@domain.com", "An email address cannot start with a period."),
        # (
        #     "twodots..here@domain.com",
        #     "An email address cannot have two periods in a row.",
        # ),
        # (
        #     "trailingdot.@domain.email",
        #     "An email address cannot have a period immediately before the @-sign.",
        # ),
        # (
        #     "me@⒈wouldbeinvalid.com",
        #     "The part after the @-sign contains invalid characters (Codepoint U+2488 not allowed "
        #     "at position 1 in '⒈wouldbeinvalid.com').",
        # ),
        # (
        #     "me@\u037e.com",
        #     "The part after the @-sign contains invalid characters after Unicode normalization: ';'.",
        # ),
        # (
        #     "me@\u1fef.com",
        #     "The part after the @-sign contains invalid characters after Unicode normalization: '`'.",
        # ),
        # ("@example.com", "There must be something before the @-sign."),
        # (
        #     "white space@test",
        #     "The email address contains invalid characters before the @-sign: SPACE.",
        # ),
        # (
        #     "test@white space",
        #     "The part after the @-sign contains invalid characters: SPACE.",
        # ),
        # (
        #     "\nmy@example.com",
        #     "The email address contains invalid characters before the @-sign: U+000A.",
        # ),
        # (
        #     "m\ny@example.com",
        #     "The email address contains invalid characters before the @-sign: U+000A.",
        # ),
        # (
        #     "my\n@example.com",
        #     "The email address contains invalid characters before the @-sign: U+000A.",
        # ),
        # (
        #     "me.\u037e@example.com",
        #     "After Unicode normalization: The email address contains invalid characters before the @-sign: ';'.",
        # ),
        # ("test@\n", "The part after the @-sign contains invalid characters: U+000A."),
        # (
        #     'bad"quotes"@example.com',
        #     "The email address contains invalid characters before the @-sign: '\"'.",
        # ),
        # (
        #     'obsolete."quoted".atom@example.com',
        #     "The email address contains invalid characters before the @-sign: '\"'.",
        # ),
        # (
        #     "11111111112222222222333333333344444444445555555555666666666677777@example.com",
        #     "The email address is too long before the @-sign (1 character too many).",
        # ),
        # (
        #     "111111111122222222223333333333444444444455555555556666666666777777@example.com",
        #     "The email address is too long before the @-sign (2 characters too many).",
        # ),
        # (
        #     "\ufb2c111111122222222223333333333444444444455555555556666666666777777@example.com",
        #     "After Unicode normalization: The email address is too long before the @-sign (2 characters too many).",
        # ),
        # (
        #     "me@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344444444445555555555.com",
        #     "The email address is too long after the @-sign (1 character too many).",
        # ),
        # (
        #     "me@中1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444.com",
        #     "The email address is too long after the @-sign (1 byte too many after IDNA encoding).",
        # ),
        # (
        #     "me@\ufb2c1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444.com",
        #     "The email address is too long after the @-sign (5 bytes too many after IDNA encoding).",
        # ),
        # (
        #     "me@1111111111222222222233333333334444444444555555555666666666677777.com",
        #     "After the @-sign, periods cannot be separated by so many characters (1 character too many).",
        # ),
        # (
        #     "me@11111111112222222222333333333344444444445555555556666666666777777.com",
        #     "After the @-sign, periods cannot be separated by so many characters (2 characters too many).",
        # ),
        # (
        #     "me@中111111111222222222233333333334444444444555555555666666.com",
        #     "The part after the @-sign is invalid (Label too long).",
        # ),
        # (
        #     "meme@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.com",
        #     "The email address is too long (4 characters too many).",
        # ),
        # (
        #     "my.long.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344444.info",
        #     "The email address is too long (2 characters too many).",
        # ),
        # (
        #     "my.long.address@λ111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
        #     "The email address is too long (1-2 characters too many).",
        # ),
        # (
        #     "my.long.address@\ufb2c111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
        #     "The email address is too long (1-3 characters too many).",
        # ),
        # (
        #     "my.λong.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.111111111122222222223333333333444.info",
        #     "The email address is too long (1 character too many).",
        # ),
        # (
        #     "my.λong.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
        #     "The email address is too long (1-2 characters too many).",
        # ),
        # (
        #     "my.\u0073\u0323\u0307.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
        #     "The email address is too long (1-2 characters too many).",
        # ),
        # (
        #     "my.\ufb2c.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344444.info",
        #     "The email address is too long (1 character too many).",
        # ),
        # (
        #     "my.\ufb2c.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344.info",
        #     "The email address is too long after normalization (1 byte too many).",
        # ),
        # (
        #     "my.long.address@λ111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333.info",
        #     "The email address is too long when the part after the @-sign is converted to IDNA ASCII (1 byte too many).",
        # ),
        # (
        #     "my.λong.address@λ111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333.info",
        #     "The email address is too long when the part after the @-sign is converted to IDNA ASCII (2 bytes too many).",
        # ),
        # (
        #     "me@bad-tld-1",
        #     "The part after the @-sign is not valid. It should have a period.",
        # ),
        # (
        #     "me@bad.tld-2",
        #     "The part after the @-sign is not valid. It is not within a valid top-level domain.",
        # ),
        # (
        #     "me@xn--0.tld",
        #     "The part after the @-sign is not valid IDNA (Invalid A-label).",
        # ),
        # (
        #     "me@yy--0.tld",
        #     "An email address cannot have two letters followed by two dashes immediately after the @-sign or after a period, except Punycode.",
        # ),
        # (
        #     "me@yy－－0.tld",
        #     "An email address cannot have two letters followed by two dashes immediately after the @-sign or after a period, except Punycode.",
        # ),
        # (
        #     "me@[127.0.0.1]",
        #     "A bracketed IP address after the @-sign is not allowed here.",
        # ),
        # (
        #     "me@[127.0.0.999]",
        #     "The address in brackets after the @-sign is not valid: It is not an IPv4 address (Octet 999 (> 255) not permitted in '127.0.0.999') or is missing an address literal tag.",
        # ),
        # (
        #     "me@[IPv6:::1]",
        #     "A bracketed IP address after the @-sign is not allowed here.",
        # ),
        # (
        #     "me@[IPv6:::G]",
        #     "The IPv6 address in brackets after the @-sign is not valid (Only hex digits permitted in 'G' in '::G').",
        # ),
        # (
        #     "me@[tag:text]",
        #     "The part after the @-sign contains an invalid address literal tag in brackets.",
        # ),
        # (
        #     "me@[untaggedtext]",
        #     "The part after the @-sign in brackets is not an IPv4 address and has no address literal tag.",
        # ),
        # (
        #     "me@[tag:invalid space]",
        #     "The part after the @-sign contains invalid characters in brackets: SPACE.",
        # ),
        # (
        #     "<me@example.com>",
        #     "A display name and angle brackets around the email address are not permitted here.",
        # ),
        # (
        #     "<me@example.com",
        #     "An open angle bracket at the start of the email address has to be followed by a close angle bracket at the end.",
        # ),
        # ("<me@example.com> !", "There can't be anything after the email address."),
        # (
        #     "<\u0338me@example.com",
        #     "The email address contains invalid characters before the @-sign: '<'.",
        # ),
        # (
        #     "DisplayName <me@-example.com>",
        #     "An email address cannot have a hyphen immediately after the @-sign.",
        # ),
        # (
        #     "DisplayName <me@example.com>",
        #     "A display name and angle brackets around the email address are not permitted here.",
        # ),
        # (
        #     "Display Name <me@example.com>",
        #     "A display name and angle brackets around the email address are not permitted here.",
        # ),
        # (
        #     '"Display Name" <me@example.com>',
        #     "A display name and angle brackets around the email address are not permitted here.",
        # ),
        # (
        #     "Display.Name <me@example.com>",
        #     "The display name contains invalid characters when not quoted: '.'.",
        # ),
        # (
        #     '"Display.Name" <me@example.com>',
        #     "A display name and angle brackets around the email address are not permitted here.",
        # ),
    ],
)
def test_email_invalid_syntax(email_input: str, error_msg: str) -> None:
    # Since these all have syntax errors, deliverability
    # checks do not arise.
    with pytest.raises(SyntaxError) as exc_info:
        validate_email(email_input, allow_smtputf8=True)
    assert str(exc_info.value) == error_msg


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
    # Since these all fail deliverabiltiy from a static list,
    # DNS deliverability checks do not arise.
    with pytest.raises(SyntaxError) as exc_info:
        validate_email(email_input)
    assert "is a special-use or reserved name" in str(exc_info.value)


@pytest.mark.parametrize(
    ("s", "expected_error"),
    [
        ("\u2005", "FOUR-PER-EM SPACE"),  # four-per-em space (Zs)
        ("\u2028", "LINE SEPARATOR"),  # line separator (Zl)
        ("\u2029", "PARAGRAPH SEPARATOR"),  # paragraph separator (Zp)
        ("\u0300", "COMBINING GRAVE ACCENT"),  # grave accent (M)
        ("\u009c", "U+009C"),  # string terminator (Cc)
        ("\u200b", "ZERO WIDTH SPACE"),  # zero-width space (Cf)
        (
            "\u202dforward-\u202ereversed",
            "LEFT-TO-RIGHT OVERRIDE, RIGHT-TO-LEFT OVERRIDE",
        ),  # BIDI (Cf)
        ("\ue000", "U+E000"),  # private use (Co)
        ("\U0010fdef", "U+0010FDEF"),  # priate use (Co)
        ("\ufdef", "U+FDEF"),  # unassigned (Cn)
    ],
)
def test_email_unsafe_character(s: str, expected_error: str) -> None:
    # Check for various unsafe characters that are permitted by the email
    # specs but should be disallowed for being unsafe or not sensible Unicode.

    with pytest.raises(SyntaxError) as exc_info:
        validate_email(s + "@test")
    assert (
        str(exc_info.value)
        == f"The email address contains invalid characters: {expected_error}."
    )

    with pytest.raises(SyntaxError) as exc_info:
        validate_email("test@" + s)
    assert "The email address contains invalid characters" in str(exc_info.value)


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
    # Check that internationalized characters are rejected if allow_smtputf8=False.
    with pytest.raises(SyntaxError) as exc_info:
        validate_email(email_input, allow_smtputf8=False, allow_quoted_local=True)
    assert str(exc_info.value) == expected_error


def test_email_empty_local() -> None:
    validate_email("@example.com", allow_empty_local=True)

    # This next one might not be desirable.
    validate_email('""@example.com', allow_empty_local=True, allow_quoted_local=True)


def test_case_insensitive_mailbox_name() -> None:
    validate_email("POSTMASTER@example.com").normalized = "postmaster@example.com"
    validate_email(
        "NOT-POSTMASTER@example.com"
    ).normalized = "NOT-POSTMASTER@example.com"
