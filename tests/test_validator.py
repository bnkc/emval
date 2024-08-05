import pytest
from emv import validate_email, ValidatedEmail


# This is the python-email-validator (https://github.com/JoshData/python-email-validator/blob/main/tests/test_syntax.py) test suite.
# testing


@pytest.mark.parametrize(
    "email_input,output",
    [
        (
            "Abc@example.tld",
            ValidatedEmail(
                local_part="Abc",
                # ascii_local_part="Abc",
                # smtputf8=False,
                # ascii_domain="example.tld",
                domain_name="example.tld",
                normalized="Abc@example.tld",
                original="Abc@example.tld",
                # ascii_email="Abc@example.tld",
            ),
        ),
        # (
        #     "Abc.123@test-example.com",
        #     MakeValidatedEmail(
        #         local_part="Abc.123",
        #         ascii_local_part="Abc.123",
        #         smtputf8=False,
        #         ascii_domain="test-example.com",
        #         domain="test-example.com",
        #         normalized="Abc.123@test-example.com",
        #         ascii_email="Abc.123@test-example.com",
        #     ),
        # ),
        # (
        #     "user+mailbox/department=shipping@example.tld",
        #     MakeValidatedEmail(
        #         local_part="user+mailbox/department=shipping",
        #         ascii_local_part="user+mailbox/department=shipping",
        #         smtputf8=False,
        #         ascii_domain="example.tld",
        #         domain="example.tld",
        #         normalized="user+mailbox/department=shipping@example.tld",
        #         ascii_email="user+mailbox/department=shipping@example.tld",
        #     ),
        # ),
        # (
        #     "!#$%&'*+-/=?^_`.{|}~@example.tld",
        #     MakeValidatedEmail(
        #         local_part="!#$%&'*+-/=?^_`.{|}~",
        #         ascii_local_part="!#$%&'*+-/=?^_`.{|}~",
        #         smtputf8=False,
        #         ascii_domain="example.tld",
        #         domain="example.tld",
        #         normalized="!#$%&'*+-/=?^_`.{|}~@example.tld",
        #         ascii_email="!#$%&'*+-/=?^_`.{|}~@example.tld",
        #     ),
        # ),
        # (
        #     "jeff@臺網中心.tw",
        #     MakeValidatedEmail(
        #         local_part="jeff",
        #         ascii_local_part="jeff",
        #         smtputf8=False,
        #         ascii_domain="xn--fiqq24b10vi0d.tw",
        #         domain="臺網中心.tw",
        #         normalized="jeff@臺網中心.tw",
        #         ascii_email="jeff@xn--fiqq24b10vi0d.tw",
        #     ),
        # ),
        # (
        #     '"quoted local part"@example.org',
        #     MakeValidatedEmail(
        #         local_part='"quoted local part"',
        #         ascii_local_part='"quoted local part"',
        #         smtputf8=False,
        #         ascii_domain="example.org",
        #         domain="example.org",
        #         normalized='"quoted local part"@example.org',
        #         ascii_email='"quoted local part"@example.org',
        #     ),
        # ),
        # (
        #     '"de-quoted.local.part"@example.org',
        #     MakeValidatedEmail(
        #         local_part="de-quoted.local.part",
        #         ascii_local_part="de-quoted.local.part",
        #         smtputf8=False,
        #         ascii_domain="example.org",
        #         domain="example.org",
        #         normalized="de-quoted.local.part@example.org",
        #         ascii_email="de-quoted.local.part@example.org",
        #     ),
        # ),
        # (
        #     "MyName <me@example.org>",
        #     MakeValidatedEmail(
        #         local_part="me",
        #         ascii_local_part="me",
        #         smtputf8=False,
        #         ascii_domain="example.org",
        #         domain="example.org",
        #         normalized="me@example.org",
        #         ascii_email="me@example.org",
        #         display_name="MyName",
        #     ),
        # ),
        # (
        #     "My Name <me@example.org>",
        #     MakeValidatedEmail(
        #         local_part="me",
        #         ascii_local_part="me",
        #         smtputf8=False,
        #         ascii_domain="example.org",
        #         domain="example.org",
        #         normalized="me@example.org",
        #         ascii_email="me@example.org",
        #         display_name="My Name",
        #     ),
        # ),
        # (
        #     r'"My.\"Na\\me\".Is" <"me \" \\ me"@example.org>',
        #     ValidatedEmail(
        #         local_part=r'"me \" \\ me"',
        #         # ascii_local_part=r'"me \" \\ me"',
        #         # smtputf8=False,
        #         # ascii_domain="example.org",
        #         domain_name="example.org",
        #         normalized=r'"me \" \\ me"@example.org',
        #         original=r'"My.\"Na\\me\".Is" <"me \" \\ me"@example.org>',
        #         # ascii_email=r'"me \" \\ me"@example.org',
        #         # display_name='My."Na\\me".Is',
        #     ),
        # ),
    ],
)
def test_email_valid(email_input: str, output: ValidatedEmail) -> None:
    # These addresses do not require SMTPUTF8. See test_email_valid_intl_local_part
    # for addresses that are valid but require SMTPUTF8. Check that it passes with
    # allow_smtput8 both on and off.
    emailinfo = validate_email(
        email_input,
        deliverable_address=False,
        allow_smtputf8=False,
        allow_quoted_local=True,
        # allow_display_name=True,
    )

    assert emailinfo == output
    assert (
        validate_email(
            email_input,
            deliverable_address=False,
            allow_smtputf8=True,
            allow_quoted_local=True,
            # allow_display_name=True,
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

    validated = validate_email(email_input, allow_quoted_local=True)

    assert validated.local_part == normalized_local_part


def test_domain_literal() -> None:
    # Check parsing IPv4 addresses.
    validated = validate_email("me@[127.0.0.1]", allow_domain_literal=True)
    assert validated.domain_name == "[127.0.0.1]"
    assert repr(validated.domain_address) == "IPv4Address('127.0.0.1')"
    #
    # Check parsing IPv6 addresses.
    validated = validate_email("me@[IPv6:::1]", allow_domain_literal=True)
    assert validated.domain_name == "[IPv6:::1]"
    assert repr(validated.domain_address) == "IPv6Address('::1')"

    # Check that IPv6 addresses are normalized.
    validated = validate_email(
        "me@[IPv6:0000:0000:0000:0000:0000:0000:0000:0001]", allow_domain_literal=True
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
        # (
        #     "me.\u037e@example.com",
        #     "After Unicode normalization: The email address contains invalid characters before the @-sign: ';'.",
        # ),
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
        # (
        #     "my.\ufb2c.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344.info",
        #     "Invalid Email Address: The email exceeds the maximum length (254 chars).",
        # ),
        # (
        #     "my.long.address@λ111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333.info",
        #     "The email address is too long when the part after the @-sign is converted to IDNA ASCII (1 byte too many).",
        # ),
        # (
        #     "my.λong.address@λ111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333.info",
        #     "The email address is too long when the part after the @-sign is converted to IDNA ASCII (2 bytes too many).",
        # ),
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
        # (
        #     "<me@example.com>",
        #     "A display name and angle brackets around the email address are not permitted here.",
        # ),
        # (
        #     "<me@example.com",
        #     "An open angle bracket at the start of the email address has to be followed by a close angle bracket at the end.",
        # ),
        # ("<me@example.com> !", "There can't be anything after the email address."),
        (
            "<\u0338me@example.com",
            "Invalid Local Part: contains invalid characters before the '@' sign.",
        ),
        (
            "DisplayName <me@-example.com>",
            "Invalid Local Part: contains invalid characters before the '@' sign.",
        ),
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
    validate_email("@example.com", allow_empty_local=True)
    validate_email('""@example.com', allow_empty_local=True, allow_quoted_local=True)


def test_case_insensitive_mailbox_name() -> None:
    validate_email("POSTMASTER@example.com").normalized = "postmaster@example.com"
    validate_email(
        "NOT-POSTMASTER@example.com"
    ).normalized = "NOT-POSTMASTER@example.com"
