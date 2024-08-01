#[macro_use]
extern crate lazy_static;

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::usize;

use idna::uts46::Uts46;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens};
use pyo3::exceptions::{PySyntaxError, PyValueError};
use pyo3::prelude::*;
use regex::bytes::Regex;
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

lazy_static! {
    // See https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3
    static ref ATEXT: &'static str = r"a-zA-Z0-9_!#\$%&'\*\+\-/=\?\^`\{\|\}~";
    static ref ATEXT_RE: Regex = Regex::new(&format!(r"[.{}]", *ATEXT)).unwrap();
    static ref DOT_ATOM_TEXT: Regex = Regex::new(&format!(r"^[{}]+(?:\.[{}]+)*$", *ATEXT, *ATEXT)).unwrap();

    // RFC 6531 3.3 extends allowed characters in internationalized addresses
    static ref ATEXT_INTL: String = format!("{}{}", *ATEXT, r"\u{0080}-\u{10FFFF}");
    static ref ATEXT_INTL_DOT_RE: Regex = Regex::new(&format!(r"[.{}]", *ATEXT_INTL)).unwrap();
    static ref DOT_ATOM_TEXT_INTL: Regex = Regex::new(&format!(r"^[{}]+(?:\.[{}]+)*$", *ATEXT_INTL, *ATEXT_INTL)).unwrap();

    // The domain part of the email address, after IDNA (ASCII) encoding,
    // must also satisfy the requirements of RFC 952/RFC 1123 2.1
    static ref ATEXT_HOSTNAME_INTL: Regex = Regex::new(r"^[a-zA-Z0-9\-\.\u{0080}-\u{10FFFF}]+$").unwrap();
    static ref HOSTNAME_LABEL: &'static str = r"(?:(?:[a-zA-Z0-9][a-zA-Z0-9\-]*)?[a-zA-Z0-9])";
    static ref DOT_ATOM_TEXT_HOSTNAME: Regex = Regex::new(&format!(r"^{}(?:\.{})*$", *HOSTNAME_LABEL, *HOSTNAME_LABEL)).unwrap();
    static ref DOMAIN_NAME_REGEX: Regex = Regex::new(r"[A-Za-z]\Z").unwrap();

    // Domain literal (RFC 5322 3.4.1)
    static ref DOMAIN_LITERAL_CHARS: Regex = Regex::new(r"[\u0021-\u00FA\u005E-\u007E]").unwrap();

    // See https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1.2
    static ref QTEXT_INTL: Regex = Regex::new(r"[\u0020-\u007E\u0080-\u{10FFFF}]").unwrap();
}

const MAX_ADDRESS_LENGTH: usize = 254;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_LOCAL_PART_LENGTH: usize = 64;
const MAX_DNS_LABEL_LENGTH: usize = 63;
const SPECIAL_USE_DOMAIN_NAMES: &[&str] =
    &["arpa", "invalid", "local", "localhost", "onion", "test"];
const CASE_INSENSITIVE_MAILBOX_NAMES: &[&str] = &[
    "info",
    "marketing",
    "sales",
    "support",
    "abuse",
    "noc",
    "security",
    "postmaster",
    "hostmaster",
    "usenet",
    "news",
    "webmaster",
    "www",
    "uucp",
    "ftp",
];

#[derive(Clone)]
#[pyclass]
struct ValidatedDomain {
    #[pyo3(get)]
    address: Option<IpAddr>,
    #[pyo3(get)]
    name: String,
}

#[pyclass]
struct ValidatedEmail {
    #[pyo3(get)]
    original: String,
    #[pyo3(get)]
    normalized: String,
    #[pyo3(get)]
    local_part: String,
    #[pyo3(get)]
    domain: ValidatedDomain,
}

#[derive(Default)]
#[pyclass]
struct EmailValidator {
    allow_smtputf8: bool,
    allow_empty_local: bool,
    allow_quoted_local: bool,
    allow_domain_literal: bool,
    deliverable_address: bool,
}

#[pymethods]
impl EmailValidator {
    #[new]
    #[pyo3(signature = (
        allow_smtputf8 = true,
        allow_empty_local = false,
        allow_quoted_local = false,
        allow_domain_literal = false,
        deliverable_address = true,

    ))]
    fn new(
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

    fn validate_email(&self, email: &str) -> PyResult<ValidatedEmail> {
        // Split the email into local part and domain
        let (unvalidated_local_part, unvalidated_domain) = _split_email(&email)?;

        // Validate length of the local part and the domain
        _validate_email_length(&unvalidated_local_part, &unvalidated_domain)?;

        // Validate local part and convert to lowercase if necessary
        let mut validated_local = self._validate_local_part(&unvalidated_local_part)?;
        if CASE_INSENSITIVE_MAILBOX_NAMES.contains(&validated_local.to_lowercase().as_str()) {
            validated_local = validated_local.to_lowercase();
        }

        // Validate the domain
        let validated_domain = self._validate_domain(&unvalidated_domain)?;

        // Construct the normalized email
        let normalized = format!("{}@{}", validated_local, validated_domain.name);

        Ok(ValidatedEmail {
            original: email.to_string(),
            local_part: validated_local,
            domain: validated_domain,
            normalized,
        })
    }

    fn _validate_local_part(&self, local: &str) -> PyResult<String> {
        // Guard clause for empty local part
        if local.is_empty() {
            return if self.allow_empty_local {
                Ok(local.to_string())
            } else {
                Err(PySyntaxError::new_err(
                    "There needs to be something before the @-sign",
                ))
            };
        }

        // Remove surrounding quotes, unescaping any escaped characters within quotes
        let unquoted_local = _unquote_local_part(local, self.allow_quoted_local)?;

        // Local part length validation
        if unquoted_local.len() > MAX_LOCAL_PART_LENGTH {
            return Err(PyValueError::new_err(
                "The email address is too long before the @-sign",
            ));
        }

        // Check for valid dot-atom text
        if DOT_ATOM_TEXT.is_match(unquoted_local.as_bytes()) {
            return Ok(unquoted_local);
        }

        // Check for valid internationalized dot-atom text
        if DOT_ATOM_TEXT_INTL.is_match(unquoted_local.as_bytes()) {
            if !self.allow_smtputf8 {
                return Err(PySyntaxError::new_err(
                    "Internationalized characters before the @-sign are not supported",
                ));
            }
            _validate_chars(&unquoted_local, false)?;

            // Check for valid UTF-8 encoding
            if String::from_utf8(unquoted_local.as_bytes().to_vec()).is_err() {
                return Err(PySyntaxError::new_err(
                    "The email address contains an invalid character",
                ));
            }

            return Ok(unquoted_local.to_string());
        }

        // Check for quoted local part and validate
        if local.starts_with('"') && local.ends_with('"') {
            let invalid_chars: HashSet<_> = local
                .chars()
                .filter(|&c| !QTEXT_INTL.is_match(c.to_string().as_bytes()))
                .collect();

            if !invalid_chars.is_empty() {
                return Err(PySyntaxError::new_err(
                    "The email address contains invalid characters in quotes before the @-sign",
                ));
            }

            let invalid_non_ascii_chars: HashSet<_> = local
                .chars()
                .filter(|&c| !(32..=126).contains(&(c as u32)))
                .collect();

            if !invalid_non_ascii_chars.is_empty() && !self.allow_smtputf8 {
                return Err(PySyntaxError::new_err(
                    "Internationalized characters before the @-sign are not supported",
                ));
            }

            _validate_chars(&unquoted_local, true)?;

            // Check for valid UTF-8 encoding
            if String::from_utf8(local.as_bytes().to_vec()).is_err() {
                return Err(PySyntaxError::new_err(
                    "The email address contains an invalid character",
                ));
            }

            return Ok(local.to_string());
        }

        // Check for other invalid characters
        let invalid_chars: HashSet<_> = unquoted_local
            .chars()
            .filter(|&c| !ATEXT_INTL_DOT_RE.is_match(c.to_string().as_bytes()))
            .collect();

        if !invalid_chars.is_empty() {
            return Err(PySyntaxError::new_err(
                "The email address contains invalid characters before the @-sign",
            ));
        }

        // Check for dot errors
        if unquoted_local.starts_with('.')
            || unquoted_local.ends_with('.')
            || unquoted_local.contains("..")
        {
            return Err(PySyntaxError::new_err("The local part of the email address cannot start or end with a dot, or contain consecutive dots"));
        }

        // Fallback error for unhandled cases
        Err(PySyntaxError::new_err(
            "The email address contains invalid characters before the @-sign.",
        ))
    }

    fn _validate_domain(&self, domain: &str) -> PyResult<ValidatedDomain> {
        // Guard clause if domain is being executed independently
        if domain.is_empty() {
            return Err(PySyntaxError::new_err(
                "There needs to be something after the @",
            ));
        }

        // Address Literals
        if domain.starts_with('[') && domain.ends_with(']') {
            if !self.allow_domain_literal {
                return Err(PyValueError::new_err("Domain Literals are not allowed"));
            }

            let domain_literal = &domain[1..domain.len() - 1];

            // Handle IPv6 addresses
            if domain_literal.starts_with("IPv6:") {
                let ipv6_literal = &domain_literal[5..];
                let addr = IpAddr::from_str(ipv6_literal).map_err(|_| {
                    PySyntaxError::new_err(
                        "The IPv6 address in brackets after the @-sign is not valid.",
                    )
                })?;
                if let IpAddr::V6(addr) = addr {
                    return Ok(ValidatedDomain {
                        name: format!("[IPv6:{}]", addr),
                        address: Some(IpAddr::V6(addr)),
                    });
                }
            }

            // Try to parse the domain literal as an IP address (either IPv4 or IPv6)
            let addr = IpAddr::from_str(domain_literal)
                .map_err(|_| PySyntaxError::new_err("Invalid domain literal"))?;

            return Ok(ValidatedDomain {
                name: match addr {
                    IpAddr::V4(_) => format!("[{}]", addr),
                    IpAddr::V6(_) => format!("[IPv6:{}]", addr),
                },
                address: Some(addr),
            });
        }

        // Check for invalid characters in the domain part
        if !ATEXT_HOSTNAME_INTL.is_match(domain.as_bytes()) {
            return Err(PySyntaxError::new_err(
                "The part after the @-sign contains invalid characters.",
            ));
        }

        // Check for unsafe characters
        _validate_chars(domain, false)?;

        // Normalize the domain using UTS-46
        let normalized_domain = Uts46::new()
            .to_ascii(
                domain.as_bytes(),
                AsciiDenyList::URL,
                Hyphens::Allow,
                DnsLength::Verify,
            )
            .map_err(|_| {
                PySyntaxError::new_err(
                    "Invalid Domain: Invalid characters after '@' sign post Unicode normalization.",
                )
            })?;

        // Check for invalid chars after normalization
        if !ATEXT_HOSTNAME_INTL.is_match(normalized_domain.as_bytes()) {
            return Err(PySyntaxError::new_err(
                "Invalid Domain: Contains invalid characters after Unicode normalization.",
            ));
        }

        // Validates the domain part of an email address based on RFC 952, RFC 1123, and RFC 5322.
        // Each label must have at least one character and cannot start or end with dashes or periods.
        // Consecutive periods and adjacent period-hyphen combinations are also invalid.
        _validate_email_domain_label(
            &normalized_domain,
            "Invalid Domain: A {} cannot immediately follow the '@' symbol.",
            "Invalid Domain: A {} cannot appear at the end of the domain.",
            true,
        )?;

        // Check the total length of the domain
        if normalized_domain.len() > MAX_DOMAIN_LENGTH {
            return Err(PyValueError::new_err("The domain is too long"));
        }

        // Check for invalid domain labels
        for label in normalized_domain.split('.') {
            if label.len() > MAX_DNS_LABEL_LENGTH {
                return Err(PyValueError::new_err("The DNS label is too long"));
            }
            // if label.starts_with('-') || label.ends_with('-') {
            //     return Err(PySyntaxError::new_err(
            //         "Invalid Domain: cannot start or end with a hyphen.",
            //     ));
            // }
            if label.is_empty() {
                return Err(PySyntaxError::new_err("The DNS label cannot be empty"));
            }
        }

        if self.deliverable_address {
            // Deliverable addresses must contain atleast one period.
            if !normalized_domain.contains(".") {
                return Err(PySyntaxError::new_err(
                    "Invalid Domain: Must contain a period ('.') to be considered valid.",
                ));
            }

            // if !DOMAIN_NAME_REGEX.is_match(normalized_domain.as_bytes()) {
            //     return Err(PySyntaxError::new_err(
            //         "The part after the @-sign is not valid",
            //     ));
            // }
        }

        // Check for reserved and "special use" domains
        for &special_domain in SPECIAL_USE_DOMAIN_NAMES {
            if normalized_domain == special_domain
                || normalized_domain.ends_with(&format!(".{}", special_domain))
            {
                return Err(PySyntaxError::new_err(
                "The part after the @-sign is a special-use or reserved name that cannot be used with email.",
            ));
            }
        }

        Ok(ValidatedDomain {
            name: normalized_domain.to_string(),
            address: None,
        })
    }
}

fn _unquote_local_part(local: &str, allow_quoted: bool) -> Result<String, PyErr> {
    if local.starts_with('"') && local.ends_with('"') {
        // Check that the quoted local part is allowed, otherwise raise exception
        if !allow_quoted {
            return Err(PySyntaxError::new_err(
                "Quoting the part before the @-sign is not allowed here.",
            ));
        }

        let mut unquoted = String::new();
        let mut chars = local[1..local.len() - 1].chars();
        let mut escaped = false;

        while let Some(c) = chars.next() {
            if escaped {
                unquoted.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else {
                unquoted.push(c);
            }
        }

        if escaped {
            return Err(PySyntaxError::new_err(
                "Trailing escape character in quoted local part",
            ));
        }

        Ok(unquoted)
    } else {
        Ok(local.to_string())
    }
}

fn _split_email(email: &str) -> Result<(String, String), PyErr> {
    let at_pos = email
        .rfind('@')
        .ok_or_else(|| PySyntaxError::new_err("Invalid Email Address: Missing an '@' symbol."))?;

    let local_part = &email[..at_pos];
    let domain_part = &email[at_pos + 1..];

    Ok((local_part.to_string(), domain_part.to_string()))
}

fn _validate_email_length(local_part: &str, domain: &str) -> Result<(), PyErr> {
    if local_part.len() + domain.len() + 1 > MAX_ADDRESS_LENGTH {
        return Err(PyValueError::new_err("The email is too long"));
    }
    Ok(())
}

fn _validate_email_domain_label(
    label: &str,
    beg_descr: &str,
    end_descr: &str,
    is_hostname: bool,
) -> Result<(), PyErr> {
    let errors = [
        (label.ends_with('.'), end_descr.replace("{}", "period")),
        (label.starts_with('.'), beg_descr.replace("{}", "period")),
        (
            label.contains(".."),
            "An email address cannot have two periods in a row.".to_string(),
        ),
        (
            is_hostname && label.ends_with('-'),
            end_descr.replace("{}", "hyphen ('-')"),
        ),
        (
            is_hostname && label.starts_with('-'),
            beg_descr.replace("{}", "hyphen ('-')"),
        ),
        (
            is_hostname && (label.contains("-.") || label.contains(".-")),
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the domain.".to_string(),
        ),
    ];

    for (condition, error) in errors.iter() {
        if *condition {
            return Err(PySyntaxError::new_err(error.clone()));
        }
    }

    Ok(())
}

fn _display_char(c: char) -> String {
    // Return safely displayable characters in quotes.
    if c == '\\' {
        return format!("\"{}\"", c);
    }
    if c.is_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace() {
        return format!("{:?}", c);
    }

    // Construct a hex string in case the unicode name doesn't exist.
    let hex = if c as u32 <= 0xFFFF {
        format!("U+{:04X}", c as u32)
    } else {
        format!("U+{:08X}", c as u32)
    };

    // Return the character name or, if it has no name, the hex string.
    if let Some(name) = unicode_names2::name(c) {
        name.to_string()
    } else {
        hex
    }
}

fn _validate_chars(s: &str, allow_space: bool) -> Result<(), PyErr> {
    let mut bad_chars = HashSet::new();

    for (i, c) in s.chars().enumerate() {
        let group = c.general_category_group();
        match group {
            GeneralCategoryGroup::Letter
            | GeneralCategoryGroup::Number
            | GeneralCategoryGroup::Punctuation
            | GeneralCategoryGroup::Symbol => {
                continue;
            }
            GeneralCategoryGroup::Separator => {
                // Spaces outside of the ASCII range.
                if !allow_space {
                    bad_chars.insert(c);
                }
            }
            GeneralCategoryGroup::Mark => {
                // Combining characters in first position or after the @-sign.
                if i == 0 {
                    bad_chars.insert(c);
                }
            }
            GeneralCategoryGroup::Other => {
                bad_chars.insert(c);
            }
        }
    }

    if !bad_chars.is_empty() {
        let mut sorted_bad_chars: Vec<char> = bad_chars.iter().cloned().collect();
        sorted_bad_chars.sort_unstable();

        let bad_chars_str = sorted_bad_chars
            .iter()
            .map(|c| _display_char(*c))
            .collect::<Vec<_>>()
            .join(", ");

        return Err(PySyntaxError::new_err(format!(
            "The email address contains invalid characters: {}.",
            bad_chars_str
        )));
    }

    Ok(())
}

#[pymodule]
fn _emv(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<EmailValidator>()?;
    m.add_class::<ValidatedEmail>()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::u8;

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
        let emv = EmailValidator::default();
        let result = emv.validate_email(email);

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
        let emv = EmailValidator::default();
        let result = emv.validate_email(email);

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
        let emv = EmailValidator::default();
        let result = emv.validate_email(email);

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
    #[case("domain.com")]
    #[case("a.com")]
    #[case("sub.domain.com")] // Subdomain
    #[case("example.co.uk")] // Country code TLD
    #[case("xn--d1acufc.xn--p1ai")] // Internationalized domain name (IDN)
    #[case("123.com")] // Numeric domain
    #[case("example.museum")] // Long TLD
    #[case("example.travel")] // Another long TLD
    #[case("e.com")] // Minimum length domain
    #[case("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com")] // Long subdomain
    fn test_validate_domain_valid(#[case] domain: &str) {
        let emv = EmailValidator::default();
        let result = emv._validate_domain(domain);

        assert!(result.is_ok());
    }

    #[rstest]
    #[case("invali*d.com")]
    #[case(&"a".repeat(64))]
    #[case("a.com-")]
    #[case("a-.com")]
    #[case(&(String::from("a") + &".com".repeat(126)))]
    #[case("example..com")] // Double dot
    #[case("example-.com")] // Trailing hyphen
    #[case("-example.com")] // Leading hyphen
    #[case("example..com")] // Consecutive dots
    #[case("example-.com")] // TLD with trailing hyphen
    #[case(".example.com")] // Leading dot
    #[case("example.com.")] // Trailing dot
    #[case("example..com")]
    #[case("example.com-")] // Trailing hyphen in second-level domain
    #[case("example..com")] // Multiple consecutive dots in second-level domain
    #[case("xn--d1acufc.xn--p1ai-")] // Internationalized domain name (IDN) with trailing hyphen
    #[case("ex_ample.com")] // Underscore in domain
    fn test_validate_domain_invalid(#[case] domain: &str) {
        let emv = EmailValidator::default();
        let result = emv._validate_domain(domain);

        assert!(result.is_err());
    }

    #[rstest]
    #[case("me@anything.arpa", false)]
    #[case("me@link.local", false)]
    #[case("me@valid.invalid", false)]
    #[case("me@host.localhost", false)]
    #[case("me@onion.onion.onion", false)]
    #[case("me@test.test.test", false)]
    fn test_special_use_domains(#[case] domain: &str, #[case] expected: bool) {
        let emv = EmailValidator::default();
        let result = emv._validate_domain(domain);

        if expected {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
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
        let emv = EmailValidator {
            allow_domain_literal: true,
            ..EmailValidator::default()
        };

        let result = emv.validate_email(email);
        assert!(result.is_ok());
        let validated_email = result.unwrap();
        assert_eq!(validated_email.domain.name, expected_domain);
        assert_eq!(validated_email.domain.address, expected_ip);
    }

    #[rstest]
    #[case("me@[300.300.300.300]")]
    #[case("me@[IPv6:2001:db8:::1:]")]
    #[case("me@[IPv6:2001:db8::85a3::8a2e:370:7334]")]
    #[case("me@[127.0.0.256]")]
    #[case("me@[IPv6:2001:db8:1234:5678:9abc:def0:1234:56789]")]
    fn test_validate_domain_literal_invalid(#[case] email: &str) {
        let emv = EmailValidator {
            allow_domain_literal: true,
            ..EmailValidator::default()
        };

        let result = emv.validate_email(email);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("example", Some("example"), false, true)]
    #[case("user.name", Some("user.name"), false, true)]
    #[case("user-name", Some("user-name"), false, true)]
    #[case("user+name", Some("user+name"), false, true)]
    #[case("user_name", Some("user_name"), false, true)]
    #[case("user123", Some("user123"), false, true)]
    #[case("1233457890", Some("1233457890"), false, true)]
    #[case("user&example.com", Some("user&example.com"), false, true)]
    fn test_validate_local_part_valid(
        #[case] input: &str,
        #[case] expected: Option<&str>,
        #[case] allow_quoted_local: bool,
        #[case] allow_smtputf8: bool,
    ) {
        let emv = EmailValidator {
            allow_quoted_local,
            allow_smtputf8,
            ..EmailValidator::default()
        };

        let result = emv._validate_local_part(input);

        if let Some(expected_local) = expected {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_local);
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case("", None, false, true)]
    #[case(&"a".repeat(MAX_LOCAL_PART_LENGTH + 1), None, false, true)]
    #[case(".user", None, false, true)]
    #[case("user.", None, false, true)]
    #[case("user..name", None, false, true)]
    #[case("user name", None, false, true)]
    #[case("user@name", None, false, true)]
    #[case("user(name", None, false, true)]
    #[case("user)name", None, false, true)]
    fn test_validate_local_part_invalid(
        #[case] input: &str,
        #[case] expected: Option<&str>,
        #[case] allow_quoted_local: bool,
        #[case] allow_smtputf8: bool,
    ) {
        let emv = EmailValidator {
            allow_quoted_local,
            allow_smtputf8,
            ..EmailValidator::default()
        };

        let result = emv._validate_local_part(input);

        if let Some(expected_local) = expected {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_local);
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case("\"user@name\"", None, false, true)]
    #[case("\"user\nname\"", None, true, false)]
    #[case("\"user\rname\"", None, true, false)]
    #[case("\"user.name\"", Some("user.name"), true, false)]
    #[case("\"user+name\"", Some("user+name"), true, false)]
    #[case("\"user_name\"", Some("user_name"), true, false)]
    #[case(
        "\"unnecessarily.quoted.local.part\"",
        Some("unnecessarily.quoted.local.part"),
        true,
        true
    )]
    #[case(
        "\"quoted.with..unicode.λ\"",
        Some("\"quoted.with..unicode.λ\""),
        true,
        true
    )]
    #[case(
        "\"unnecessarily.quoted.with.unicode.λ\"",
        Some("unnecessarily.quoted.with.unicode.λ"),
        true,
        true
    )]
    #[case("\"quoted..local.part\"", Some("\"quoted..local.part\""), true, true)]
    #[case("\"quoted.with.at@\"", Some("\"quoted.with.at@\""), true, true)]
    #[case("\"quoted with space\"", Some("\"quoted with space\""), true, true)]
    #[case(
        "\"quoted.with.dquote\\\"\"",
        Some("\"quoted.with.dquote\\\"\""),
        true,
        false
    )]
    #[case(
        "\"quoted.with.extraneous.\\escape\"",
        Some("quoted.with.extraneous.escape"),
        true,
        false
    )]
    fn test_validate_local_part_quoted(
        #[case] input: &str,
        #[case] expected: Option<&str>,
        #[case] allow_quoted_local: bool,
        #[case] allow_smtputf8: bool,
    ) {
        let emv = EmailValidator {
            allow_quoted_local,
            allow_smtputf8,
            ..EmailValidator::default()
        };

        let result = emv._validate_local_part(input);

        if let Some(expected_local) = expected {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_local);
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case("username", false)]
    #[case("user-name", false)]
    #[case("user.name", false)]
    #[case("", false)]
    #[case("\u{00E9}", false)] // Unicode character é
    #[case("user\u{00E9}name", false)] // Unicode character é in the middle
    #[case("user\u{00E9}", false)] // Unicode character é at the end
    #[case("\u{03B1}\u{03B2}\u{03B3}", false)] // Greek characters
    #[case("user\u{03B1}\u{03B2}\u{03B3}name", false)] // Greek characters in the middle
    #[case("\u{4E00}\u{4E8C}\u{4E09}", false)] // Chinese characters
    #[case("user\u{4E00}\u{4E8C}\u{4E09}name", false)] // Chinese characters in the middle
    #[case("user_name", false)]
    #[case("user+name", false)]
    #[case("user=name", false)]
    #[case("user&name", false)]
    fn test_validate_chars_valid(#[case] input: &str, #[case] allow_space: bool) {
        let result = _validate_chars(input, allow_space);

        assert!(result.is_ok());
    }

    #[rstest]
    #[case("user\x01name", false)]
    #[case("user\u{2028}name", false)] // Unicode line separator
    #[case("user\u{2029}name", false)] // Unicode paragraph separator
    #[case("user\u{E000}name", false)] // Unicode private use character
    #[case("\u{0301}username", false)] // Combining character
    #[case("user\u{007F}name", false)] // Unicode delete character
    #[case("user\nname", false)]
    #[case("user\tname", false)]
    #[case("\u{FEFF}", false)] // Unicode byte order mark
    #[case("user\u{FEFF}name", false)] // Unicode byte order mark in the middle
    fn test_validate_chars_invalid(#[case] input: &str, #[case] allow_space: bool) {
        let result = _validate_chars(input, allow_space);

        assert!(result.is_err());
    }

    #[rstest]
    #[case("user name", true, true)]
    #[case("user  name", true, true)]
    #[case("user name", false, false)]
    #[case("user  name", false, false)]
    fn test_validate_chars_with_and_without_spaces(
        #[case] input: &str,
        #[case] allow_space: bool,
        #[case] expected: bool,
    ) {
        let result = _validate_chars(input, allow_space);

        if expected {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case("example@domain.com")]
    #[case("user.name+tag+sorting@example.com")]
    #[case("x@example.com")]
    #[case("example-indeed@strange-example.com")]
    #[case("a@b.c")] // Minimum length valid email
    #[case("valid_email@sub.domain.com")] // Subdomain
    #[case("valid-email@domain.co.jp")] // Country code TLD
    #[case("invalid-email@domain..com")] // Double dot in domain
    #[case("@missing-local.org")] // Can be missing Local
    #[case("missing-domain@")] // Can be missing Domain
    fn test_split_email_valid(#[case] input: &str) {
        let result = _split_email(input);

        assert!(result.is_ok());
    }

    #[rstest]
    #[case("plainaddress")]
    #[case("missing-at-sign.com")]
    #[case("")]
    fn test_split_email_invalid(#[case] input: &str) {
        let result = _split_email(input);

        assert!(result.is_err());
    }
}
