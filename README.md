# 📬 emval

<p align="center">
  <a href="LICENSE" alt="License">
    <img alt="GitHub License" src="https://img.shields.io/github/license/bnkc/emval?style=for-the-badge"></a>
  <a href="https://github.com/bnkc/emval/releases" alt="Releases">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/bnkc/emval?style=for-the-badge&logo=github"></a>
  <a href="https://github.com/bnkc/emval/commits/main/" alt="Latest Commits">
    <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/bnkc/emval?style=for-the-badge&logo=github"></a>
  <a href="https://github.com/bnkc/emval/actions" alt="Build Status">
    <img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/bnkc/emval/CI.yml?style=for-the-badge&logo=github"></a>
  <a href="https://crates.io/crates/emval" alt="bnkc on crates.io">
    <img alt="Crates.io Version" src="https://img.shields.io/crates/v/emval?style=for-the-badge&logo=rust&logoColor=red&color=red"></a>
  <a href="https://docs.rs/emval" alt="Rustitude documentation on docs.rs">
    <img alt="docs.rs" src="https://img.shields.io/docsrs/emval?style=for-the-badge&logo=rust&logoColor=red"></a>
  <a href="https://pypi.org/project/emval/" alt="PyPI">
    <img alt="PyPI" src="https://img.shields.io/pypi/v/emval?style=for-the-badge&logo=pypi&logoColor=yellow"></a>
</p>

`emval` is a blazingly fast email validator written in Rust with Python bindings, offering performance improvements of 100-1000x over traditional validators.

![performance image](https://raw.githubusercontent.com/bnkc/emval/b90cc4a0ae24e329702872c4fb1cccf212d556a6/perf.svg)

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

Install `emval` from PyPI:

```sh
pip install emval
```

or use `emval` in a Rust project:
```sh
cargo add emval
```

## Usage

### Quick Start

To validate an email address in Python:

```python
from emval import validate_email, EmailValidator

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

The same code in Rust:
```rust
use emval::{validate_email, ValidationError};

fn main() -> Result<(), ValidationError> {
    let email = "example@domain.com";
    let val_email = validate_email(email)?;
    let normalized_email = val_email.normalized;
    Ok(())
}
```

### Configurations

Customize email validation behavior using the `EmailValidator` class:

```python
from emval import EmailValidator

emval = EmailValidator(
    allow_smtputf8=False,
    allow_empty_local=True,
    allow_quoted_local=True,
    allow_domain_literal=True,
    deliverable_address=False,
    allowed_special_domains=['test', 'invalid'],
)

email = "user@[192.168.1.1]"

try:
    validated_email = emval.validate_email(email)
    print(validated_email)
except Exception as e:
    print(str(e))
```

The same code in Rust:
```rust
use emval::{EmailValidator, ValidationError};

fn main() -> Result<(), ValidationError> {
    let emval = EmailValidator {
        allow_smtputf8: false,
        allow_empty_local: true,
        allow_quoted_local: true,
        allow_domain_literal: true,
        deliverable_address: false,
        allowed_special_domains: vec!["test".to_string(), "invalid".to_string()],
    };

    let email = "example@domain.com";
    let validated_email = emval.validate_email(email)?;
    Ok(())
}
```

### Options

- `allow_smtputf8`: Allows internationalized email addresses.
- `allow_empty_local`: Allows an empty local part (e.g., `@domain.com`).
- `allow_quoted_local`: Allows quoted local parts (e.g., `"user name"@domain.com`).
- `allow_domain_literal`: Allows domain literals (e.g., `[192.168.0.1]`).
- `deliverable_address`: Checks if the email address is deliverable by verifying the domain's MX records.
- `allowed_special_domains`: List of special-use domains to allow despite being reserved (e.g., `['test', 'invalid']`).

## Polars Plugin

emval includes a high-performance Polars plugin for validating email addresses in DataFrames at scale.

### Installation

The Polars plugin is included when you install emval:

```sh
pip install emval
```

### Usage

Import the `validate_email` function from `emval.polars` and use it with Polars expressions:

```python
import polars as pl
from emval.polars import validate_email

# Create a DataFrame with email addresses
df = pl.DataFrame({
    "email": [
        "user@example.com",
        "invalid-email",
        "another.user@domain.org",
        ""
    ]
})

# Validate emails and add results as a struct column
result = df.with_columns(
    validated=validate_email(
        pl.col("email"),
        allow_smtputf8=True,
        allow_empty_local=False,
        allow_quoted_local=False,
        allow_domain_literal=False,
        deliverable_address=False,
        allowed_special_domains=[]
    )
)

# Extract individual fields from the validation result
result = result.with_columns(
    original=pl.col("validated").struct.field("original"),
    normalized=pl.col("validated").struct.field("normalized"),
    local_part=pl.col("validated").struct.field("local_part"),
    domain_address=pl.col("validated").struct.field("domain_address"),
    domain_name=pl.col("validated").struct.field("domain_name"),
    is_deliverable=pl.col("validated").struct.field("is_deliverable"),
)

print(result)
```

### Return Fields

The `validate_email` function returns a struct with the following fields:

- `original`: The original email address (null if invalid)
- `normalized`: The normalized form of the email address (null if invalid)
- `local_part`: The local part of the email address (null if invalid)
- `domain_address`: The IP address if a domain literal was used (null otherwise)
- `domain_name`: The domain name (null if invalid)
- `is_deliverable`: Whether the email is deliverable based on MX records (null if invalid or not checked)

Invalid emails will have all fields set to null, making it easy to filter valid emails:

```python
# Filter to only valid emails
valid_emails = result.filter(pl.col("normalized").is_not_null())
```

### Performance Benefits

The Polars plugin leverages Rust's performance and Polars' columnar architecture to validate millions of email addresses efficiently. This is ideal for:

- Data cleaning and validation pipelines
- Batch processing of user data
- ETL workflows
- Large-scale email list verification

## Technical Details

### Email Address Syntax

emval adheres to the syntax rules defined in [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html). It supports both ASCII and internationalized characters.

### Internationalized Email Addresses

#### Domain Names

emval converts non-ASCII domain names into their ASCII "Punycode" form according to [IDNA 2008](https://www.rfc-editor.org/rfc/rfc5891.html). This ensures compatibility with systems that do not support Unicode.

#### Local Parts

emval allows international characters in the local part of email addresses, following [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html). It offers options to handle environments without SMTPUTF8 support.

### Unsafe Unicode Characters

emval rejects unsafe Unicode characters to enhance security, preventing display and interpretation issues.

### Normalization

emval normalizes email addresses to ensure consistency:

- **Lowercasing domains:** Domain names are standardized to lowercase.
- **Unicode NFC normalization:** Characters are transformed into their precomposed forms.
- **Removing unnecessary characters:** Quotes and backslashes in the local part are removed.

## Acknowledgements

This project draws inspiration from [python-email-validator](https://github.com/JoshData/python-email-validator). While `python-email-validator` is more comprehensive, `emval` aims to provide a faster solution.

## Getting Help

For questions and issues, please open an issue in the [GitHub issue tracker](https://github.com/bnkc/emval/issues).

## License

emval is licensed under the [MIT License](https://opensource.org/licenses/MIT). See the [LICENSE](https://github.com/bnkc/emval/blob/main/LICENSE) file for more details.
