#[macro_use]
extern crate lazy_static;

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::usize;

use idna::uts46::Uts46;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens};
use pyo3::exceptions::PyValueError;
use pyo3::{create_exception, prelude::*};
use regex::bytes::Regex;
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

lazy_static! {
    // Based on RFC 5322 3.2.3
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

    // Quoted-string local part (RFC 5321 4.1.2, internationalized by RFC 6531 3.3)
    static ref QTEXT_INTL: Regex = Regex::new(r"[\u0020-\u007E\u0080-\u{10FFFF}]").unwrap();
}

const MAX_EMAIL_ADDRESS_LENGTH: usize = 254;
const MAX_EMAIL_DOMAIN_LENGTH: usize = 253;
const MAX_EMAIL_LOCAL_PART_LENGTH: usize = 64;
const MAX_DNS_LABEL_LENGTH: usize = 63;

create_exception!(emv, SyntaxError, PyValueError);
create_exception!(emv, DomainLiteralError, PyValueError);
create_exception!(emv, LengthError, PyValueError);

#[pyclass]
#[derive(Debug)]
pub struct ValidatedEmail {
    pub local_part: String,
    pub domain: String,
    pub is_valid: bool,
}

#[derive(Debug)]
pub struct EmailParts {
    pub local_part: String,
    pub domain: String,
}

#[pyclass]
pub struct EmailValidator {
    allow_smtputf8: bool,
    allow_empty_local: bool,
    allow_quoted_local: bool,
    allow_domain_literal: bool,
    allow_display_name: bool,
    check_deliverability: bool,
    globally_deliverable: bool,
    timeout: Option<u64>,
}

#[pymethods]
impl EmailValidator {
    #[new]
    fn new() -> Self {
        Self {
            allow_smtputf8: false,
            allow_empty_local: false,
            allow_quoted_local: false,
            allow_domain_literal: false,
            allow_display_name: false,
            check_deliverability: false,
            globally_deliverable: false,
            timeout: None,
        }
    }

    pub fn email(&self, email: &str) -> PyResult<ValidatedEmail> {
        // split email into local part and domain
        let parts = split_email(&email)?;
        let local_part = parts.local_part;
        let domain = parts.domain;

        // Validate local part
        self.local_part(&local_part)?;

        // Validate domain
        self.domain(&domain)?;

        let validated_email = ValidatedEmail {
            local_part,
            domain,
            is_valid: true,
        };

        // Validate length
        validate_length(&validated_email)?;

        Ok(validated_email)
    }

    pub fn local_part(&self, local_part: &str) -> PyResult<()> {
        // validate local part of the email
        if local_part.is_empty() && !self.allow_empty_local {
            return Err(SyntaxError::new_err(
                "There needs to be something before the the @-sign".to_string(),
            ));
        }

        // Check the length of the local part
        if local_part.len() > MAX_EMAIL_LOCAL_PART_LENGTH {
            return Err(LengthError::new_err(
                "The email address is too long befoe the @-sign".to_string(),
            ));
        }

        // Check for dot errors
        if local_part.starts_with('.') || local_part.ends_with('.') || local_part.contains("..") {
            return Err(SyntaxError::new_err(
                "The local part of the email address cannot start or end with a dot, or contain consecutive dots".to_string(),
            ));
        }

        // Checks for valid characters as per RFC 5322 3.2.3.
        if DOT_ATOM_TEXT.is_match(local_part.as_bytes()) {
            return Ok(());
        }

        // Check for internationalized local part
        if DOT_ATOM_TEXT_INTL.is_match(local_part.as_bytes()) {
            if !self.allow_smtputf8 {
                return Err(SyntaxError::new_err(
                    "Internationalized characters before the @-sign are not supported".to_string(),
                ));
            }
        }

        // Check for quoted local part
        if self.allow_quoted_local {
            let bad_chars: HashSet<_> = local_part
                .chars()
                .filter(|&c| !QTEXT_INTL.is_match(c.to_string().as_bytes()))
                .collect();

            if !bad_chars.is_empty() {
                return Err(SyntaxError::new_err(
                    "The email address contains invalid characters in quotes before the @-sign"
                        .to_string(),
                ));
            }

            // Check for non-ASCII range characters
            let bad_chars: HashSet<_> = local_part
                .chars()
                .filter(|&c| !(32..=126).contains(&(c as u32)))
                .collect();

            if !bad_chars.is_empty() {
                if !self.allow_smtputf8 {
                    return Err(SyntaxError::new_err(
                        "Internationalized characters before the @-sign are not supported"
                            .to_string(),
                    ));
                }
            }

            // Check for unsafe characters
            validate_chars(local_part, true)?;

            // Try encoding to UTF-8
            if let Err(_) = String::from_utf8(local_part.as_bytes().to_vec()) {
                return Err(SyntaxError::new_err(
                    "The email address contains an invalid character".to_string(),
                ));
            }

            return Ok(());
        }

        // Check for invalid characters (RFC 5322 3.2.3, plus RFC 6531 3.3)
        let bad_chars: HashSet<_> = local_part
            .chars()
            .filter(|&c| !ATEXT_INTL_DOT_RE.is_match(c.to_string().as_bytes()))
            .collect();

        if !bad_chars.is_empty() {
            return Err(SyntaxError::new_err(
                "The email address contains invalid characters before the @-sign".to_string(),
            ));
        }

        Ok(())
    }

    pub fn domain(&self, domain: &str) -> PyResult<()> {
        // Check if the domain is empty
        if domain.is_empty() {
            return Err(SyntaxError::new_err(
                "There needs to be something after the @".to_string(),
            ));
        }

        // Validate domain literal
        if domain.starts_with('[') && domain.ends_with(']') {
            if !self.allow_domain_literal {
                return Err(DomainLiteralError::new_err(
                    "Domain Literals are not allowed".to_string(),
                ));
            }
            let domain_literal = &domain[1..domain.len() - 1];
            if IpAddr::from_str(domain_literal).is_err() {
                return Err(DomainLiteralError::new_err(
                    "Invalid domain literal".to_string(),
                ));
            }
            return Ok(());
        }

        // Check for invalid characters in the domain part
        if !ATEXT_HOSTNAME_INTL.is_match(domain.as_bytes()) {
            return Err(SyntaxError::new_err(
                "The part after the @-sign contains invalid characters.".to_string(),
            ));
        }

        // Check for unsafe characters
        validate_chars(domain, false)?;

        // Normalize the domain
        let uts46 = Uts46::new();
        let normalized_domain = match uts46.to_ascii(
            domain.as_bytes(),
            AsciiDenyList::URL,
            Hyphens::Allow,
            DnsLength::Verify,
        ) {
            Ok(norm) => norm,
            Err(err) => {
                return Err(SyntaxError::new_err(format!(
                    "The part after the @-sign contains invalid characters ({:?})",
                    err
                )))
            }
        };

        // Check for invalid chars after normalization
        if !ATEXT_HOSTNAME_INTL.is_match(domain.as_bytes()) {
            return Err(SyntaxError::new_err(
                "The part after the @-sign contains invalid characters.".to_string(),
            ));
        }

        // Check for dot errors
        if normalized_domain.starts_with('.')
            || normalized_domain.ends_with('.')
            || normalized_domain.contains("..")
        {
            return Err(SyntaxError::new_err(
                "The email address cannot start or end with a dot, or contain consecutive dots"
                    .to_string(),
            ));
        }

        // Check for invalid domain labels
        for label in normalized_domain.split('.') {
            if label.len() > MAX_DNS_LABEL_LENGTH {
                return Err(LengthError::new_err(
                    "The DNS label is too long".to_string(),
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(SyntaxError::new_err(
                    "The DNS label cannot start or end with a hyphen".to_string(),
                ));
            }
            if label.len() == 0 {
                return Err(SyntaxError::new_err(
                    "The DNS label cannot be empty".to_string(),
                ));
            }
        }

        // Check the total length of the domain
        if normalized_domain.len() > MAX_EMAIL_DOMAIN_LENGTH {
            return Err(LengthError::new_err("The domain is too long".to_string()));
        }

        Ok(())
    }
}

fn unquote_local_part(local: &str) -> Result<String, PyErr> {
    if local.starts_with('"') && local.ends_with('"') {
        let mut unquoted = String::new();
        let mut chars = local[1..local.len() - 1].chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.peek() {
                    if *next == '\\' || *next == '"' {
                        unquoted.push(c);
                        continue;
                    }
                }
                return Err(SyntaxError::new_err(
                    "Invalid escape sequence in quoted local part",
                ));
            } else {
                unquoted.push(c);
            }
        }
        Ok(unquoted)
    } else {
        Ok(local.to_string())
    }
}

fn split_email(email: &str) -> Result<EmailParts, PyErr> {
    let at_pos = email
        .rfind('@')
        .ok_or_else(|| SyntaxError::new_err("Invalid email: missing @"))?;

    let local_part = &email[..at_pos];
    let domain_part = &email[at_pos + 1..];

    if local_part.is_empty() || domain_part.is_empty() {
        return Err(SyntaxError::new_err(
            "Invalid email: local or domain part is empty",
        ));
    }

    // Handle quoted local parts, unescaping any escaped characters within quotes.
    let local_part = unquote_local_part(local_part)?;

    Ok(EmailParts {
        local_part,
        domain: domain_part.to_string(),
    })
}

fn validate_length(email: &ValidatedEmail) -> Result<(), PyErr> {
    // Validate email length
    if email.local_part.len() + email.domain.len() + 1 > MAX_EMAIL_ADDRESS_LENGTH {
        return Err(LengthError::new_err("The email is too long".to_string()));
    }
    Ok(())
}

fn validate_chars(s: &str, allow_space: bool) -> Result<(), PyErr> {
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
        let bad_chars_str = bad_chars.into_iter().collect::<String>();
        return Err(SyntaxError::new_err(format!(
            "The email address contains unsafe characters: {}.",
            bad_chars_str
        )));
    }

    Ok(())
}

#[pymodule]
fn emv(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<EmailValidator>()?;
    m.add_class::<ValidatedEmail>()?;

    m.add("SyntaxError", _py.get_type_bound::<SyntaxError>())?;
    m.add(
        "DomainLiteralError",
        _py.get_type_bound::<DomainLiteralError>(),
    )?;
    m.add("LengthError", _py.get_type_bound::<LengthError>())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        let validate = EmailValidator::new();

        // Valid email addresses
        assert!(validate.email("example@domain.com").is_ok());
        assert!(validate.email("user.name+tag+sorting@example.com").is_ok());
        assert!(validate.email("x@example.com").is_ok());
        assert!(validate.email("example-indeed@strange-example.com").is_ok());

        // Invalid email addresses
        assert!(validate.email("plainaddress").is_err());
        assert!(validate.email("@missing-local.org").is_err());
        assert!(validate.email("missing-domain@.com").is_err());
        assert!(validate.email("missing-at-sign.com").is_err());
        assert!(validate.email("missing-tld@domain.").is_err());
        assert!(validate.email("invalid-char@domain.c*m").is_err());
        assert!(validate.email("too..many..dots@domain.com").is_err());
    }

    #[test]
    fn test_validate_domain() {
        let mut validate = EmailValidator::new();
        assert!(validate.domain("domain.com").is_ok());
        assert!(validate.domain("invali*d.com").is_err()); // Invalid character
        validate.allow_domain_literal = true;
        assert!(validate.domain("[192.168.1.1]").is_ok());
        assert!(validate.domain("a.com").is_ok()); // Valid domain
        assert!(validate.domain("a".repeat(64).as_str()).is_err()); // Label too long
        assert!(validate.domain("a.com-").is_err()); // Label ends with hyphen
        assert!(validate.domain("a-.com").is_err()); // Label starts with hyphen
        assert!(validate
            .domain(&(String::from("a") + &".com".repeat(126)))
            .is_err()); // Domain too long
    }

    #[test]
    fn test_validate_local_part() {
        let validate = EmailValidator::new();

        assert!(validate.local_part("example").is_ok());
        assert!(validate.local_part("user.name").is_ok());
        assert!(validate.local_part("user-name").is_ok());
        assert!(validate.local_part("user+name").is_ok());
        assert!(validate.local_part("user_name").is_ok());
        assert!(validate.local_part("user123").is_ok());
        assert!(validate.local_part("1233457890").is_ok());
        assert!(validate.local_part("user&example.com").is_ok());

        // Invalid local parts - empty local part
        assert!(validate.local_part("").is_err());

        // Invalid local parts - too long
        let long_local_part = "a".repeat(MAX_EMAIL_LOCAL_PART_LENGTH + 1);
        assert!(validate.local_part(&long_local_part).is_err());

        // Invalid local parts - starts with dot
        assert!(validate.local_part(".user").is_err());

        // Invalid local parts - ends with dot
        assert!(validate.local_part("user.").is_err());

        // Invalid local parts - contains consecutive dots
        assert!(validate.local_part("user..name").is_err());

        // Invalid local parts - contains spaces
        assert!(validate.local_part("user name").is_err());

        // Invalid local parts - contains special characters not allowed. Certain characters are
        // allowed: ._!#$%&'^``*+-=~/?{|}
        assert!(validate.local_part("user@name").is_err());
        assert!(validate.local_part("user(name").is_err());
        assert!(validate.local_part("user)name").is_err());

        // Valid internationalized local parts
        let validate_with_smtputf8 = EmailValidator {
            allow_smtputf8: true,
            ..EmailValidator::new()
        };

        assert!(validate_with_smtputf8.local_part("用户").is_ok());
        assert!(validate_with_smtputf8.local_part("θσερ").is_ok());
        assert!(validate_with_smtputf8.local_part("коля").is_ok());
        assert!(validate_with_smtputf8.local_part("δοκιμή").is_ok());
        assert!(validate_with_smtputf8.local_part("üsername").is_ok());

        // Valid internationalized local parts
        let validate_no_smtputf8 = EmailValidator {
            allow_smtputf8: false,
            ..EmailValidator::new()
        };

        assert!(validate_no_smtputf8.local_part("üsername").is_err());

        // Invalid local parts - quoted local parts with invalid characters
        assert!(validate.local_part("\"user@name\"").is_err());
        assert!(validate.local_part("\"user\nname\"").is_err());
        assert!(validate.local_part("\"user\rname\"").is_err());

        // Valid quoted local parts
        let validate_with_quoted = EmailValidator {
            allow_quoted_local: true,
            ..EmailValidator::new()
        };

        assert!(validate_with_quoted.local_part("\"user name\"").is_ok());
        assert!(validate_with_quoted.local_part("\"user@name\"").is_ok());
        assert!(validate_with_quoted.local_part("\"user.name\"").is_ok());
        assert!(validate_with_quoted.local_part("\"user+name\"").is_ok());
        assert!(validate_with_quoted.local_part("\"user_name\"").is_ok());
    }

    #[test]
    fn test_unsafe_chars() {
        // Allow space
        assert!(validate_chars("user name", true).is_ok());

        // Disallow space
        assert!(validate_chars("user name", false).is_err());

        // Control characters
        assert!(validate_chars("user\x01name", false).is_err());

        // Line and paragraph separators
        assert!(validate_chars("user\u{2028}name", false).is_err());
        assert!(validate_chars("user\u{2029}name", false).is_err());

        // Private use characters
        assert!(validate_chars("user\u{E000}name", false).is_err());

        // Combining characters at the start
        assert!(validate_chars("\u{0301}username", false).is_err());

        // Valid characters
        assert!(validate_chars("username", false).is_ok());
        assert!(validate_chars("user-name", false).is_ok());
        assert!(validate_chars("user.name", false).is_ok());
    }

    #[test]
    fn test_split_email() {
        // Valid email addresses
        assert!(split_email("example@domain.com").is_ok());
        assert!(split_email("user.name+tag+sorting@example.com").is_ok());
        assert!(split_email("x@example.com").is_ok());
        assert!(split_email("example-indeed@strange-example.com").is_ok());

        // Invalid email addresses
        assert!(split_email("plainaddress").is_err());
        assert!(split_email("@missing-local.org").is_err());
        assert!(split_email("missing-domain@").is_err());
        assert!(split_email("missing-at-sign.com").is_err());
    }
}
