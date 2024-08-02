# Emv

[![EMV](https://img.shields.io/pypi/v/emv.svg)](https://pypi.python.org/pypi/emv)
[![License](https://img.shields.io/pypi/l/emv.svg)](https://github.com/your-repo/emv/blob/main/LICENSE)
[![Python Versions](https://img.shields.io/pypi/pyversions/emv.svg)](https://pypi.python.org/pypi/emv)
[![CI](https://github.com/your-repo/emv/actions/workflows/ci.yml/badge.svg)](https://github.com/your-repo/emv/actions)


[**Docs**](https://docs.your-repo.com/emv/) | [**GitHub**](https://github.com/your-repo/emv)

EMV is a fast and robust email validation library for Python, utilizing a Rust backend to ensure optimal performance. This package is designed to enhance and speed up the functionality of the older `python-email-validator` library.

<p align="center">
  <img src="https://your-image-url.com/benchmark.svg" alt="Benchmark Results">
</p>

<p align="center">
  <i>Benchmark comparing EMV with other email validation libraries.</i>
</p>

- 🚀 Lightning-fast validation powered by Rust
- 📦 Available on PyPI for easy installation
- 🌐 Supports internationalized email addresses (IDN)
- 🛠️ Configurable validation settings
- 📜 Detailed error messages
- 🔄 Normalizes email addresses
- ✅ RFC 5322 and RFC 6531 compliance

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Configuration](#configuration)
5. [Technical Details](#technical-details)
6. [Examples](#examples)
7. [Contributing](#contributing)
8. [Support](#support)
9. [Acknowledgements](#acknowledgements)
10. [License](#license)

## Getting Started

For comprehensive documentation, visit the [official docs](https://docs.your-repo.com/emv/).

### Installation

Install EMV from PyPI:

```sh
pip install emv
```

### Usage

To validate an email address:

```python
from emv import validate_email

email = "example@domain.com"

try:
    validated_email = validate_email(email)
    print(validated_email)
except Exception as e:
    print(f"Validation error: {e}")
```

## Configuration

You can customize the email validation behavior using the `EmailValidator` class:

```python
from emv import EmailValidator

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

## Contributing

Contributions are welcome and highly appreciated. To get started, check out the [**contributing guidelines**](https://github.com/your-repo/emv/blob/main/CONTRIBUTING.md).

You can also join us on [**Discord**](https://discord.com/invite/your-discord-invite).

## Support

Having trouble? Check out the existing issues on [**GitHub**](https://github.com/your-repo/emv/issues), or feel free to [**open a new one**](https://github.com/your-repo/emv/issues/new).

You can also ask for help on [**Discord**](https://discord.com/invite/your-discord-invite).

## Acknowledgements

EMV draws inspiration from the `python-email-validator` library and other email validation tools. We are grateful to the maintainers of these tools for their work and the value they provide to the Python community.

## License

This repository is licensed under the [MIT License](https://github.com/your-repo/emv/blob/main/LICENSE). See the [LICENSE](LICENSE) file for more details.

<div align="center">
  <a target="_blank" href="https://your-company.com" style="background:none">
    <img src="https://your-image-url.com/your-logo.svg" alt="Made by Your Company">
  </a>
</div>
