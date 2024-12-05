use pyo3::prelude::*;
use std::net::IpAddr;

/// A structure representing a validated email address with various components and normalized forms.
#[pyclass]
pub struct ValidatedEmail {
    /// The email address provided to validate_email.
    #[pyo3(get)]
    pub original: String,
    /// The normalized email address should be used instead of the original. It converts IDNA ASCII domain names to Unicode and normalizes both the local part and domain. The normalized address combines the local part and domain name with an '@' sign.
    #[pyo3(get)]
    pub normalized: String,
    /// The local part of the email address (the part before the '@' sign) after it has been Unicode normalized.
    #[pyo3(get)]
    pub local_part: String,
    /// If the domain part is a domain literal, it will be an IPv4Address or IPv6Address object.
    #[pyo3(get)]
    pub domain_address: Option<IpAddr>,
    /// The domain part of the email address (the part after the '@' sign) after Unicode normalization.
    #[pyo3(get)]
    pub domain_name: String,
    /// Whether the email address is deliverable.
    #[pyo3(get)]
    pub is_deliverable: bool,
}

/// A structure for customizing email validation.
#[pyclass]
pub struct EmailValidator {
    /// Whether to allow SMTPUTF8. [Default: true]
    pub allow_smtputf8: bool,
    /// Whether to allow empty local part. [Default: false]
    pub allow_empty_local: bool,
    /// Whether to allow quoted local part. [Default: false]
    pub allow_quoted_local: bool,
    /// Whether to allow domain literals. [Default: false]
    pub allow_domain_literal: bool,
    /// Whether to check if the email address is deliverable. [Default: true]
    pub deliverable_address: bool,
}

impl Default for EmailValidator {
    fn default() -> Self {
        Self {
            allow_smtputf8: true,
            allow_empty_local: false,
            allow_quoted_local: false,
            allow_domain_literal: false,
            deliverable_address: true,
        }
    }
}
