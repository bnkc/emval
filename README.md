# 📧 EMV

EMV is a fast and robust email validation library designed to handle complex email validation needs with the backend written in Rust for enhanced performance. This package is an optimized version aimed at speeding up the older python-email-validator library.

```python
from emv import validate_email, EmailValidator

email = "example@domain.com"

try:
    validated_email = validate_email(email)
    print(validated_email)
except Exception as e:
    print(f"Validation error: {e}")
```

## Installation

Install EMV from PyPI:

```sh
pip install emv
```

## Features

- Validates email address syntax according to RFC 5322 and RFC 6531
- Checks domain deliverability
- Supports internationalized domain names (IDN) and local parts
- Provides friendly error messages
- Optimized for performance with Rust backend

## Usage

### Quick Start

To validate an email address:

```python
from emv import validate_email, EmailValidator

email = "example@domain.com"

try:
    validated_email = validate_email(email)
    print(validated_email)
except Exception as e:
    print(f"Validation error: {e}")
```

### Configurations

You can customize the email validation behavior using the `EmailValidator` class:

```python
validator = EmailValidator(
    allow_smtputf8=True,
    allow_empty_local=False,
    allow_quoted_local=False,
    allow_domain_literal=False,
    deliverable_address=True,
)

email = "example@domain.com"

try:
    validated_email = validator.validate_email(email)
    print(validated_email)
except Exception as e:
    print(f"Validation error: {e}")
```

### Options

- `allow_smtputf8` (default: `True`): Allows internationalized email addresses.
- `allow_empty_local` (default: `False`): Allows an empty local part (e.g., `@domain.com`).
- `allow_quoted_local` (default: `False`): Allows quoted local parts (e.g., `"user name"@domain.com`).
- `allow_domain_literal` (default: `False`): Allows domain literals (e.g., `[192.168.0.1]`).
- `deliverable_address` (default: `True`): Checks if the email address is deliverable by verifying the domain's MX records.

## Technical Details

### Email Address Syntax

EMV follows the syntax rules defined in [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html) for email address validation. The library ensures that the local part and domain of the email address conform to the specified standards, including support for internationalized characters.

### Normalization

The library normalizes email addresses to ensure consistency. This includes lowercasing the domain part, Unicode NFC normalization, and removing unnecessary quotes and backslashes in the local part.

### Error Handling

EMV provides clear and concise error messages to help users understand why an email address is invalid. The errors are categorized into syntax errors, domain errors, and length errors.

## Examples

### Basic Validation

```python
from emv import validate_email

email = "user@example.com"

try:
    validated_email = validate_email(email)
    print(validated_email)
except Exception as e:
    print(f"Validation error: {e}")
```

### Validation with Custom Settings

```python
from emv import EmailValidator

validator = EmailValidator(
    allow_smtputf8=False,
    allow_empty_local=True,
    allow_quoted_local=True,
    allow_domain_literal=True,
    deliverable_address=False,
)

email = "user@[192.168.1.1]"

try:
    validated_email = validator.validate_email(email)
    print(validated_email)
except Exception as e:
    print(f"Validation error: {e}")
```

### Handling Errors

```python
from emv import validate_email

email = "invalid-email"

try:
    validated_email = validate_email(email)
    print(validated_email)
except Exception as e:
    print(f"Validation error: {e}")
```

## Getting Help

For questions and issues, please open an issue in the [GitHub issue tracker](https://github.com/your-repo/emv/issues).

## License

EMV is licensed under the [MIT License](https://opensource.org/licenses/MIT). See the [LICENSE](LICENSE) file for more details.
