use pyo3::prelude::*;
use std::net::IpAddr;

#[pyclass]
pub struct ValidatedEmail {
    #[pyo3(get)]
    pub original: String,
    #[pyo3(get)]
    pub normalized: String,
    #[pyo3(get)]
    pub local_part: String,
    #[pyo3(get)]
    pub domain_address: Option<IpAddr>,
    #[pyo3(get)]
    pub domain_name: String,
}

#[derive(Default)]
#[pyclass]
pub struct EmailValidator {
    pub allow_smtputf8: bool,
    pub allow_empty_local: bool,
    pub allow_quoted_local: bool,
    pub allow_domain_literal: bool,
    pub deliverable_address: bool,
}
