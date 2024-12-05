use crate::models::EmailValidator;
use crate::models::ValidatedEmail;

use pyo3::prelude::*;

impl EmailValidator {
    /// Validates an email address.
    ///
    /// # Examples
    ///
    /// ```
    /// use emval::EmailValidator;
    ///
    /// let validator = EmailValidator::default();
    /// let validated_email = validator.validate_email("example@domain.com").unwrap();
    /// assert!(validated_email.is_deliverable);
    ///
    /// ```
    pub fn validate_email(
        &self,
        email: &str,
    ) -> Result<ValidatedEmail, crate::errors::ValidationError> {
        let (unvalidated_local_part, unvalidated_domain) = crate::validators::split_email(email)?;

        crate::validators::validate_email_length(&unvalidated_local_part, &unvalidated_domain)?;

        let mut valid_local_part =
            crate::validators::validate_local_part(self, &unvalidated_local_part)?;

        if crate::consts::CASE_INSENSITIVE_MAILBOX_NAMES
            .contains(&valid_local_part.to_lowercase().as_str())
        {
            valid_local_part = valid_local_part.to_lowercase();
        }

        let (domain_name, domain_address) =
            crate::validators::validate_domain(self, &unvalidated_domain)?;

        if self.deliverable_address {
            crate::validators::validate_deliverability(&domain_name)?;
        }

        let normalized = format!("{}@{}", valid_local_part, domain_name);

        Ok(ValidatedEmail {
            original: email.to_string(),
            local_part: valid_local_part,
            domain_name,
            domain_address,
            normalized,
            is_deliverable: true,
        })
    }
}

#[pymethods]
impl EmailValidator {
    /// Create a new email validator with the given settings.
    ///
    /// # Arguments
    ///
    /// * `allow_smtputf8`: Whether to allow SMTPUTF8. [Default: true]
    /// * `allow_empty_local`: Whether to allow empty local part. [Default: false]
    /// * `allow_quoted_local`: Whether to allow quoted local part. [Default: false]
    /// * `allow_domain_literal`: Whether to allow domain literals. [Default: false]
    /// * `deliverable_address`: Whether to check if the email address is deliverable. [Default: true]
    #[new]
    #[pyo3(signature = (
        allow_smtputf8 = true,
        allow_empty_local = false,
        allow_quoted_local = false,
        allow_domain_literal = false,
        deliverable_address = true,

    ))]
    pub fn new(
        allow_smtputf8: bool,
        allow_empty_local: bool,
        allow_quoted_local: bool,
        allow_domain_literal: bool,
        deliverable_address: bool,
    ) -> Self {
        EmailValidator {
            allow_smtputf8,
            allow_empty_local,
            allow_quoted_local,
            allow_domain_literal,
            deliverable_address,
        }
    }

    #[pyo3(name = "validate_email")]
    fn py_validate_email(&self, email: &str) -> PyResult<ValidatedEmail> {
        self.validate_email(email).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::net::IpAddr;
    use std::str::FromStr;

    // Helper functions
    fn ipv4(octets: [u8; 4]) -> Option<IpAddr> {
        Some(IpAddr::V4(std::net::Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        )))
    }

    fn ipv6(addr: &str) -> Option<IpAddr> {
        Some(IpAddr::V6(std::net::Ipv6Addr::from_str(addr).unwrap()))
    }

    #[rstest]
    #[case("example@domain.com", Some("example@domain.com"))]
    #[case(
        "user.name+tag+sorting@example.com",
        Some("user.name+tag+sorting@example.com")
    )]
    #[case("x@example.com", Some("x@example.com"))]
    #[case(
        "example-indeed@strange-example.com",
        Some("example-indeed@strange-example.com")
    )]
    fn test_validate_email_valid(#[case] email: &str, #[case] expected: Option<&str>) {
        let emval = EmailValidator {
            allow_smtputf8: false,
            allow_empty_local: false,
            allow_quoted_local: false,
            allow_domain_literal: false,
            deliverable_address: false,
        };
        let result = emval.validate_email(email);

        match expected {
            Some(expected_normalized) => {
                assert!(result.is_ok());
                let validated_email = result.unwrap();
                assert_eq!(validated_email.normalized, expected_normalized);
            }
            None => {
                assert!(result.is_err());
            }
        }
    }

    #[rstest]
    #[case("plainaddress", None)]
    #[case("@missing-local.org", None)]
    #[case("missing-domain@.com", None)]
    #[case("missing-at-sign.com", None)]
    #[case("missing-tld@domain.", None)]
    #[case("invalid-char@domain.c*m", None)]
    #[case("too..many..dots@domain.com", None)]
    fn test_validate_email_invalid(#[case] email: &str, #[case] expected: Option<&str>) {
        let emval = EmailValidator::default();
        let result = emval.validate_email(email);

        match expected {
            Some(expected_normalized) => {
                assert!(result.is_ok());
                let validated_email = result.unwrap();
                assert_eq!(validated_email.normalized, expected_normalized);
            }
            None => {
                assert!(result.is_err());
            }
        }
    }

    #[rstest]
    #[case("POSTMASTER@example.com", Some("postmaster@example.com"))]
    #[case("NOT-POSTMASTER@example.com", Some("NOT-POSTMASTER@example.com"))]
    fn test_validate_email_case_insensitive(#[case] email: &str, #[case] expected: Option<&str>) {
        let emval = EmailValidator {
            allow_smtputf8: false,
            allow_empty_local: false,
            allow_quoted_local: false,
            allow_domain_literal: false,
            deliverable_address: false,
        };
        let result = emval.validate_email(email);

        match expected {
            Some(expected_normalized) => {
                assert!(result.is_ok());
                let validated_email = result.unwrap();
                assert_eq!(validated_email.normalized, expected_normalized);
            }
            None => {
                assert!(result.is_err());
            }
        }
    }

    #[rstest]
    #[case("me@[127.0.0.1]", "[127.0.0.1]", ipv4([127, 0, 0, 1]))]
    #[case("me@[192.168.0.1]", "[192.168.0.1]", ipv4([192, 168, 0, 1]))]
    #[case("me@[IPv6:::1]", "[IPv6:::1]", ipv6("::1"))]
    #[case(
        "me@[IPv6:0000:0000:0000:0000:0000:0000:0000:0001]",
        "[IPv6:::1]",
        ipv6("::1")
    )]
    #[case("me@[IPv6:2001:db8::1]", "[IPv6:2001:db8::1]", ipv6("2001:db8::1"))]
    #[case(
        "me@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
        "[IPv6:2001:db8:85a3::8a2e:370:7334]",
        ipv6("2001:db8:85a3::8a2e:370:7334")
    )]
    #[case(
        "me@[IPv6:2001:db8:1234:5678:9abc:def0:1234:5678]",
        "[IPv6:2001:db8:1234:5678:9abc:def0:1234:5678]",
        ipv6("2001:db8:1234:5678:9abc:def0:1234:5678")
    )]
    fn test_validate_domain_literal_valid(
        #[case] email: &str,
        #[case] expected_domain: &str,
        #[case] expected_ip: Option<IpAddr>,
    ) {
        let emval = EmailValidator {
            allow_domain_literal: true,
            allow_smtputf8: false,
            allow_empty_local: false,
            allow_quoted_local: false,
            deliverable_address: false,
        };

        let result = emval.validate_email(email);
        assert!(result.is_ok());
        let validated_email = result.unwrap();
        assert_eq!(validated_email.domain_name, expected_domain);
        assert_eq!(validated_email.domain_address, expected_ip);
    }
}
