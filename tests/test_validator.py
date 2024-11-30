import pytest

from emval import ValidatedEmail, validate_email

# This is the python-email-validator (https://github.com/JoshData/python-email-validator/blob/main/tests/test_syntax.py) test suite.
# It has been slightly modified and does not cover all edge cases, including display names and checking dns_resolver


@pytest.mark.parametrize(
    "email_input,output",
    [
        (
            "Abc@example.tld",
            ValidatedEmail(
                local_part="Abc",
                domain_name="example.tld",
                normalized="Abc@example.tld",
                original="Abc@example.tld",
            ),
        ),
        (
            "Abc.123@test-example.com",
            ValidatedEmail(
                local_part="Abc.123",
                domain_name="test-example.com",
                normalized="Abc.123@test-example.com",
                original="Abc.123@test-example.com",
            ),
        ),
        (
            "user+mailbox/department=shipping@example.tld",
            ValidatedEmail(
                local_part="user+mailbox/department=shipping",
                domain_name="example.tld",
                normalized="user+mailbox/department=shipping@example.tld",
                original="user+mailbox/department=shipping@example.tld",
            ),
        ),
        (
            "!#$%&'*+-/=?^_`.{|}~@example.tld",
            ValidatedEmail(
                local_part="!#$%&'*+-/=?^_`.{|}~",
                domain_name="example.tld",
                normalized="!#$%&'*+-/=?^_`.{|}~@example.tld",
                original="!#$%&'*+-/=?^_`.{|}~@example.tld",
            ),
        ),
        (
            '"quoted local part"@example.org',
            ValidatedEmail(
                local_part='"quoted local part"',
                domain_name="example.org",
                normalized='"quoted local part"@example.org',
                original='"quoted local part"@example.org',
            ),
        ),
        (
            '"de-quoted.local.part"@example.org',
            ValidatedEmail(
                local_part="de-quoted.local.part",
                domain_name="example.org",
                normalized="de-quoted.local.part@example.org",
                original='"de-quoted.local.part"@example.org',
            ),
        ),
    ],
)
def test_email_valid(email_input: str, output: ValidatedEmail) -> None:
    validated_email = validate_email(
        email_input,
        deliverable_address=False,
        allow_smtputf8=False,
        allow_quoted_local=True,
    )

    assert validated_email == output
    assert (
        validate_email(
            email_input,
            deliverable_address=False,
            allow_smtputf8=True,
            allow_quoted_local=True,
        )
        == output
    )


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
    with pytest.raises(SyntaxError) as exc_info:
        validate_email(email_input)

    assert (
        str(exc_info.value)
        == "Invalid Local Part: Quoting the local part before the '@' sign is not permitted in this context."
    )

    validated = validate_email(
        email_input,
        allow_quoted_local=True,
        deliverable_address=False,
    )

    assert validated.local_part == normalized_local_part


def test_domain_literal() -> None:
    # Check parsing IPv4 addresses.
    validated = validate_email(
        "me@[127.0.0.1]", allow_domain_literal=True, deliverable_address=False
    )
    assert validated.domain_name == "[127.0.0.1]"
    assert repr(validated.domain_address) == "IPv4Address('127.0.0.1')"
    #
    # Check parsing IPv6 addresses.
    validated = validate_email(
        "me@[IPv6:::1]", allow_domain_literal=True, deliverable_address=False
    )
    assert validated.domain_name == "[IPv6:::1]"
    assert repr(validated.domain_address) == "IPv6Address('::1')"

    # Check that IPv6 addresses are normalized.
    validated = validate_email(
        "me@[IPv6:0000:0000:0000:0000:0000:0000:0000:0001]",
        allow_domain_literal=True,
        deliverable_address=False,
    )
    assert validated.domain_name == "[IPv6:::1]"
    assert repr(validated.domain_address) == "IPv6Address('::1')"


@pytest.mark.parametrize(
    "email_input,error_msg",
    [
        ("hello.world", "Invalid Email Address: Missing an '@' sign."),
        (
            "my@localhost",
            "Invalid Domain: Must contain a period ('.') to be considered valid.",
        ),
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
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the email address.",
        ),
        (
            "my@baddash.-a.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the email address.",
        ),
        (
            "my@baddash.b-.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the email address.",
        ),
        (
            "my@baddashfw.－.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the email address.",
        ),
        (
            "my@baddashfw.－a.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the email address.",
        ),
        (
            "my@baddashfw.b－.com",
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the email address.",
        ),
        (
            "my@example.com\n",
            "Invalid Domain: Contains invalid characters after '@' sign.",
        ),
        (
            "my@example\n.com",
            "Invalid Domain: Contains invalid characters after '@' sign.",
        ),
        (
            "me@x!",
            "Invalid Domain: Contains invalid characters after '@' sign.",
        ),
        (
            "me@x ",
            "Invalid Domain: Contains invalid characters after '@' sign.",
        ),
        (".leadingdot@domain.com", "Invalid Local Part: Cannot start with a period."),
        (
            "twodots..here@domain.com",
            "Invalid Email Address: Two periods ('.') cannot be adjacent in the email address.",
        ),
        (
            "trailingdot.@domain.email",
            "Invalid Local Part: A period cannot immediately precede the '@' sign.",
        ),
        (
            "me@⒈wouldbeinvalid.com",
            "Invalid Domain: Contains invalid characters after '@' sign post Unicode normalization.",
        ),
        (
            "me@\u037e.com",
            "Invalid Domain: Contains invalid characters after Unicode normalization.",
        ),
        (
            "me@\u1fef.com",
            "Invalid Domain: Contains invalid characters after Unicode normalization.",
        ),
        (
            "@example.com",
            "Invalid Local Part: The part before the '@' sign cannot be empty.",
        ),
        (
            "white space@test",
            "Invalid Local Part: contains invalid characters before the '@' sign.",
        ),
        (
            "test@white space",
            "Invalid Domain: Contains invalid characters after '@' sign.",
        ),
        (
            "\nmy@example.com",
            "Invalid Local Part: contains invalid characters before the '@' sign.",
        ),
        (
            "m\ny@example.com",
            "Invalid Local Part: contains invalid characters before the '@' sign.",
        ),
        (
            "my\n@example.com",
            "Invalid Local Part: contains invalid characters before the '@' sign.",
        ),
        ("test@\n", "Invalid Domain: Contains invalid characters after '@' sign."),
        (
            'bad"quotes"@example.com',
            "Invalid Local Part: contains invalid characters before the '@' sign.",
        ),
        (
            'obsolete."quoted".atom@example.com',
            "Invalid Local Part: contains invalid characters before the '@' sign.",
        ),
        (
            "11111111112222222222333333333344444444445555555555666666666677777@example.com",
            "Invalid Local Part: The part before the '@' sign exceeds the maximum length (64 chars).",
        ),
        (
            "111111111122222222223333333333444444444455555555556666666666777777@example.com",
            "Invalid Local Part: The part before the '@' sign exceeds the maximum length (64 chars).",
        ),
        (
            "\ufb2c111111122222222223333333333444444444455555555556666666666777777@example.com",
            "Invalid Local Part: The part before the '@' sign exceeds the maximum length (64 chars).",
        ),
        (
            "me@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344444444445555555555.com",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "me@中1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444.com",
            "Invalid Domain: Contains invalid characters after '@' sign post Unicode normalization.",
        ),
        (
            "me@\ufb2c1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444.com",
            "Invalid Domain: Contains invalid characters after '@' sign post Unicode normalization.",
        ),
        # (
        #     "me@中111111111222222222233333333334444444444555555555666666.com",
        #     "The part after the @-sign is invalid (Label too long).",
        # ),
        (
            "meme@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.com",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "my.long.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344444.info",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "my.long.address@λ111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "my.long.address@\ufb2c111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "my.λong.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.111111111122222222223333333333444.info",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "my.λong.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "my.\u0073\u0323\u0307.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "my.\ufb2c.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344444.info",
            "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        ),
        (
            "me@bad-tld-1",
            "Invalid Domain: Must contain a period ('.') to be considered valid.",
        ),
        (
            "me@bad.tld-2",
            "Invalid domain: The part after the '@' sign does not belong to a valid top-level domain (TLD).",
        ),
        (
            "me@xn--0.tld",
            "Invalid Domain: Contains invalid characters after '@' sign post Unicode normalization.",
        ),
        (
            "me@yy--0.tld",
            "Invalid Domain: Two letters followed by two dashes ('--') are not allowed immediately after the '@' sign or a period.",
        ),
        (
            "me@yy－－0.tld",
            "Invalid Domain: Two letters followed by two dashes ('--') are not allowed immediately after the '@' sign or a period.",
        ),
        (
            "me@[127.0.0.999]",
            "Invalid Domain: The address in brackets following the '@' sign is not a valid IP address.",
        ),
        (
            "me@[IPv6:::G]",
            "Invalid Domain: The IPv6 address in brackets following the '@' symbol is not valid.",
        ),
        (
            "me@[tag:text]",
            "Invalid Domain: The address in brackets following the '@' sign is not a valid IP address.",
        ),
        (
            "me@[untaggedtext]",
            "Invalid Domain: The address in brackets following the '@' sign is not a valid IP address.",
        ),
        (
            "me@[tag:invalid space]",
            "Invalid Domain: The address in brackets following the '@' sign is not a valid IP address.",
        ),
    ],
)
def test_email_invalid_syntax(email_input: str, error_msg: str) -> None:
    with pytest.raises((SyntaxError, ValueError)) as exc_info:
        validate_email(email_input, allow_smtputf8=True, allow_domain_literal=True)
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
    with pytest.raises(SyntaxError) as exc_info:
        validate_email(email_input)
    assert (
        "Invalid Domain: The part after the '@' sign is a reserved or special-use domain that cannot be used."
        in str(exc_info.value)
    )


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
    with pytest.raises(SyntaxError) as exc_info:
        validate_email(s + "@test")
    assert (
        str(exc_info.value)
        == f"Invalid Email Address: contains invalid characters: {expected_error}."
    )

    with pytest.raises(SyntaxError) as exc_info:
        validate_email("test@" + s)
    assert "Invalid Email Address: contains invalid characters:" in str(exc_info.value)


@pytest.mark.parametrize(
    ("email_input", "expected_error"),
    [
        (
            "λambdaツ@test",
            "Invalid Local Part: Internationalized characters before the '@' sign are not supported.",
        ),
        (
            '"quoted.with..unicode.λ"@example.com',
            "Invalid Local Part: Internationalized characters before the '@' sign are not supported.",
        ),
    ],
)
def test_email_invalid_character_smtputf8_off(
    email_input: str, expected_error: str
) -> None:
    with pytest.raises(SyntaxError) as exc_info:
        validate_email(email_input, allow_smtputf8=False, allow_quoted_local=True)
    assert str(exc_info.value) == expected_error


def test_email_empty_local() -> None:
    validate_email("@example.com", allow_empty_local=True, deliverable_address=False)
    validate_email(
        '""@example.com',
        allow_empty_local=True,
        allow_quoted_local=True,
        deliverable_address=False,
    )


def test_case_insensitive_mailbox_name() -> None:
    assert (
        validate_email("POSTMASTER@example.com", deliverable_address=False).normalized
        == "postmaster@example.com"
    )

    assert (
        validate_email(
            "NOT-POSTMASTER@example.com", deliverable_address=False
        ).normalized
        == "NOT-POSTMASTER@example.com"
    )


@pytest.mark.parametrize(
    "domain,expected_response",
    [
        (
            "test@gmail.com",
            True,
        ),
        (
            "test@pages.github.com",
            True,
        ),
    ],
)
def test_deliverability_found(domain: str, expected_response: bool) -> None:
    response = validate_email(domain, deliverable_address=True)
    assert response.is_deliverable == expected_response


@pytest.mark.parametrize(
    ("domain", "error"),
    [
        (
            "test@xkxufoekjvjfjeodlfmdfjcu.com",
            "Invalid Domain: No MX, A, or AAAA records found for domain.",
        ),
        (
            "test@example.com",
            "Invalid Domain: The domain does not accept email due to a null MX record, indicating it is not configured to receive emails.",
        ),
        (
            "test@g.mail.com",
            "Invalid Domain: No MX, A, or AAAA records found for domain.",
        ),
        (
            "test@justtxt.joshdata.me",
            "Invalid Domain: No MX, A, or AAAA records found for domain.",
        ),
    ],
)
def test_deliverability_fails(domain: str, error: str) -> None:
    with pytest.raises(SyntaxError, match=error):
        validate_email(domain, deliverable_address=True)
