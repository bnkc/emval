# 📬 emv

`emv` is a blazingly fast python email validator written in rust that is between _100-1000x_ faster than the next email validator.

![performance image](https://raw.githubusercontent.com/bnkc/emv/a529464cc8add6497105fe53116ba40903082f7b/perf.svg)

## Features

- Drop in replacement for common email validators such as python-email-validator, verify-email, pyIsEmail.
- 100-1000x faster than [python-email-validator](https://github.com/JoshData/python-email-validator).
- Validates email address syntax according to [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html).
- Checks domain deliverability. _(coming soon)_
- Supports internationalized domain names (IDN) and local parts.
- Provides user friendly syntax errors.
- Normalized addresses.
- Rejects Invalid and Unsafe unicode characters.

## Getting Started

The open source version of `emv` can be installed from PyPI:

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

    # Check if the email is valid. You can also provide several flags as shown below.
    val_email = validate_email(email)

    # The function returns a ValidatedEmail Object,
    # from which you can utilize `normalized` to write to a DB.
    normalized_email = val_email.normalized
    
except Exception as e:
    # Example: "Invalid Local Part: Quoting the local part before the '@' sign is not permitted in this context."
    print(str(e))
```

### Configurations

You can customize the email validation behavior using the `EmailValidator` class once, if more convenient:

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
    print(str(r))
```

### Options

- `allow_smtputf8`: Allows internationalized email addresses.
- `allow_empty_local`: Allows an empty local part (e.g., `@domain.com`).
- `allow_quoted_local`: Allows quoted local parts (e.g., `"user name"@domain.com`).
- `allow_domain_literal`: Allows domain literals (e.g., `[192.168.0.1]`).
- `deliverable_address`: Checks if the email address is deliverable by verifying the domain's MX records.

## Technical Details

### Email Address Syntax

EMV follows the syntax rules defined in [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html) for email address validation. The library ensures that the local part and domain of the email address conform to the specified standards, including support for internationalized characters.

### Normalization

The library normalizes email addresses to ensure consistency. This includes lowercasing the domain part, Unicode NFC normalization, and removing unnecessary quotes and backslashes in the local part.


## Getting Help

For questions and issues, please open an issue in the [GitHub issue tracker](https://github.com/bnkc/emv/issues).
## License

EMV is licensed under the [MIT License](https://opensource.org/licenses/MIT). See the [LICENSE]([LICENSE](https://github.com/bnkc/emv/blob/main/LICENSE)) file for more details.
