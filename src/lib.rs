//! # 📬 emval
//!
//! `emval` is a blazingly fast email validator written in Rust with Python bindings, offering performance improvements of 100-1000x over traditional validators.
//!
//! ![performance image](https://raw.githubusercontent.com/bnkc/emval/b90cc4a0ae24e329702872c4fb1cccf212d556a6/perf.svg)

//! ## Features

//! - Drop-in replacement for popular email validators like `python-email-validator`, `verify-email`, and `pyIsEmail`.
//! - 100-1000x faster than [python-email-validator](https://github.com/JoshData/python-email-validator).
//! - Validates email address syntax according to [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html).
//! - Checks domain deliverability (coming soon).
//! - Supports internationalized domain names (IDN) and local parts.
//! - Provides user-friendly syntax errors.
//! - Normalizes addresses.
//! - Rejects invalid and unsafe Unicode characters.
//!
//! ## Getting Started
//!
//! Install `emval` from PyPI:
//!
//! ```sh
//! pip install emval
//! ```
//!
//! or use `emval` in a Rust project:
//! ```sh
//! cargo add emval
//! ```
//!
//! ## Usage
//!
//! ### Quick Start
//!
//! To validate an email address in Python:
//!
//! ```python
//! from emval import validate_email, EmailValidator
//!
//! email = "example@domain.com"
//!
//! try:
//!     # Check if the email is valid.
//!     val_email = validate_email(email)
//!     # Utilize the normalized form for storage.
//!     normalized_email = val_email.normalized
//! except Exception as e:
//!     # Example: "Invalid Local Part: Quoting the local part before the '@' sign is not permitted in this context."
//!     print(str(e))
//! ```
//!
//! The same code in Rust:
//! ```rust
//! use emval::{validate_email, ValidationError};
//!
//! fn main() -> Result<(), ValidationError> {
//!     let email = "example@domain.com";
//!     let val_email = validate_email(email)?;
//!     let normalized_email = val_email.normalized;
//!     Ok(())
//! }
//! ```
//!
//! ### Configurations
//!
//! Customize email validation behavior using the `EmailValidator` class:
//!
//! ```python
//! from emval import EmailValidator
//!
//! emval = EmailValidator(
//!     allow_smtputf8=False,
//!     allow_empty_local=True,
//!     allow_quoted_local=True,
//!     allow_domain_literal=True,
//!     deliverable_address=False,
//! )
//!
//! email = "user@[192.168.1.1]"
//!
//! try:
//!     validated_email = emval.validate_email(email)
//!     print(validated_email)
//! except Exception as e:
//!     print(str(e))
//! ```
//!
//! The same code in Rust:
//! ```rust
//! use emval::{EmailValidator, ValidationError};
//!
//! fn main() -> Result<(), ValidationError> {
//!     let emval = EmailValidator {
//!         allow_smtputf8: false,
//!         allow_empty_local: true,
//!         allow_quoted_local: true,
//!         allow_domain_literal: true,
//!         deliverable_address: false,
//!         allowed_special_domains: Vec::new(),
//!     };
//!
//!     let email = "example@domain.com";
//!     let validated_email = emval.validate_email(email)?;
//!     Ok(())
//! }
//! ```
//!
//! ### Options
//!
//! - `allow_smtputf8`: Allows internationalized email addresses.
//! - `allow_empty_local`: Allows an empty local part (e.g., `@domain.com`).
//! - `allow_quoted_local`: Allows quoted local parts (e.g., `"user name"@domain.com`).
//! - `allow_domain_literal`: Allows domain literals (e.g., `[192.168.0.1]`).
//! - `deliverable_address`: Checks if the email address is deliverable by verifying the domain's MX records.
//!
//! ## Technical Details
//!
//! ### Email Address Syntax
//!
//! emval adheres to the syntax rules defined in [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) and [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html). It supports both ASCII and internationalized characters.
//!
//! ### Internationalized Email Addresses
//!
//! #### Domain Names
//!
//! emval converts non-ASCII domain names into their ASCII "Punycode" form according to [IDNA 2008](https://www.rfc-editor.org/rfc/rfc5891.html). This ensures compatibility with systems that do not support Unicode.
//!
//! #### Local Parts
//!
//! emval allows international characters in the local part of email addresses, following [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531.html). It offers options to handle environments without SMTPUTF8 support.
//!
//! ### Unsafe Unicode Characters
//!
//! emval rejects unsafe Unicode characters to enhance security, preventing display and interpretation issues.
//!
//! ### Normalization
//!
//! emval normalizes email addresses to ensure consistency:
//!
//! - **Lowercasing domains:** Domain names are standardized to lowercase.
//! - **Unicode NFC normalization:** Characters are transformed into their precomposed forms.
//! - **Removing unnecessary characters:** Quotes and backslashes in the local part are removed.
//!
//! ## Acknowledgements
//!
//! This project draws inspiration from [python-email-validator](https://github.com/JoshData/python-email-validator). While `python-email-validator` is more comprehensive, `emval` aims to provide a faster solution.
//!
//! ## Getting Help
//!
//! For questions and issues, please open an issue in the [GitHub issue tracker](https://github.com/bnkc/emval/issues).
//!
//! ## License
//!
//! emval is licensed under the [MIT License](https://opensource.org/licenses/MIT). See the [LICENSE](https://github.com/bnkc/emval/blob/main/LICENSE) file for more details.

mod consts;
pub mod errors;
mod models;
#[cfg(feature = "polars")]
mod polars_plugin;
pub(crate) mod util;
mod validators;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;



pub use crate::errors::ValidationError;
pub use crate::models::{EmailValidator, ValidatedEmail};

/// Validate an email with default validator settings.
pub fn validate_email<T: AsRef<str>>(email: T) -> Result<ValidatedEmail, ValidationError> {
    let validator = EmailValidator::default();
    validator.validate_email(email.as_ref())
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn validate_email_wasm(email: String) -> Result<String, String> {
    match validate_email(&email) {
        Ok(validated) => Ok(validated.normalized),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
fn _emval(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<models::EmailValidator>()?;
    m.add_class::<models::ValidatedEmail>()?;

    Ok(())
}
