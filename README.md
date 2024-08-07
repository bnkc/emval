# 📬 EMV

`emv` is a blazingly fast Python email validator written in Rust, offering performance improvements of 100-1000x over traditional validators.

![performance image](https://raw.githubusercontent.com/bnkc/emv/e4fe97ee7feb643a3534342bb15421512d6efa15/perf.svg)

## Features

- Drop-in replacement for popular email validators like `python-email-validator`, `verify-email`, and `pyIsEmail`.
- 100-1000x faster than [python-email-validator](https://github.com/JoshData/python-email-validator).
- Validates email address syntax according to [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html).
- Checks domain deliverability (coming soon).
- Supports internationalized domain names (IDN) and local parts.
- Provides user-friendly syntax errors.
- Normalizes addresses.
- Rejects invalid and unsafe Unicode characters.

## Getting Started

Install `emv` from PyPI:

```sh
pip install emv
```

## Usage

### Quick Start

To validate an email address:

```python
from emv import validate_email, EmailValidator

email = "example@domain.com"

try:
    # Check if the email is valid.
    val_email = validate_email(email)
    # Utilize the normalized form for storage.
    normalized_email = val_email.normalized
except Exception as e:
    # Example: "Invalid Local Part: Quoting the local part before the '@' sign is not permitted in this context."
    print(str(e))
```

### Configurations

Customize email validation behavior using the `EmailValidator` class:

```python
from emv import EmailValidator

emv = EmailValidator(
    allow_smtputf8=False,
    allow_empty_local=True,
    allow_quoted_local=True,
    allow_domain_literal=True,
    deliverable_address=False,
)

email = "user@[192.168.1.1]"

try:
    validated_email = emv.validate_email(email)
    print(validated_email)
except Exception as e:
    print(str(e))
```

### Options

- `allow_smtputf8`: Allows internationalized email addresses.
- `allow_empty_local`: Allows an empty local part (e.g., `@domain.com`).
- `allow_quoted_local`: Allows quoted local parts (e.g., `"user name"@domain.com`).
- `allow_domain_literal`: Allows domain literals (e.g., `[192.168.0.1]`).
- `deliverable_address`: Checks if the email address is deliverable by verifying the domain's MX records.

## Technical Details

### Email Address Syntax

EMV adheres to the syntax rules defined in [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html). It supports both ASCII and internationalized characters.

### Internationalized Email Addresses

#### Domain Names

EMV converts non-ASCII domain names into their ASCII "Punycode" form according to [IDNA 2008](https://www.rfc-editor.org/rfc/rfc5891.html). This ensures compatibility with systems that do not support Unicode.

#### Local Parts

EMV allows international characters in the local part of email addresses, following [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html). It offers options to handle environments without SMTPUTF8 support.

### Unsafe Unicode Characters

EMV rejects unsafe Unicode characters to enhance security, preventing display and interpretation issues.

### Normalization

EMV normalizes email addresses to ensure consistency:

- **Lowercasing domains:** Domain names are standardized to lowercase.
- **Unicode NFC normalization:** Characters are transformed into their precomposed forms.
- **Removing unnecessary characters:** Quotes and backslashes in the local part are removed.

## Acknowledgements

This project draws inspiration from [python-email-validator](https://github.com/JoshData/python-email-validator). While `python-email-validator` is more comprehensive, `emv` aims to provide a faster solution.

## Getting Help

For questions and issues, please open an issue in the [GitHub issue tracker](https://github.com/bnkc/emv/issues).

## License

EMV is licensed under the [MIT License](https://opensource.org/licenses/MIT). See the [LICENSE](https://github.com/bnkc/emv/blob/main/LICENSE) file for more details.
