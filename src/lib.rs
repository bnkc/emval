#[macro_use]
extern crate lazy_static;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::usize;

use idna::uts46::Uts46;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens};
use pyo3::exceptions::PyValueError;
use pyo3::{create_exception, prelude::*};
use regex::bytes::Regex;
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

lazy_static! {
    // 3.2.3.  Atom
    //
    // atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
    //                     "!" / "#" /        ;  characters not including
    //                     "$" / "%" /        ;  specials.  Used for atoms.
    //                     "&" / "'" /
    //                     "*" / "+" /
    //                     "-" / "/" /
    //                     "=" / "?" /
    //                     "^" / "_" /
    //                     "`" / "{" /
    //                     "|" / "}" /
    //                     "~"
    //
    // atom            =   [CFWS] 1*atext [CFWS]
    //
    // dot-atom-text   =   1*atext *("." 1*atext)
    //
    // dot-atom        =   [CFWS] dot-atom-text [CFWS]
    //
    // specials        =   "(" / ")" /        ; Special characters that do
    //                     "<" / ">" /        ;  not appear in atext
    //                     "[" / "]" /
    //                     ":" / ";" /
    //                     "@" / "\" /
    //                     "," / "." /
    //
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

    // 4.1.2.  Command Argument Syntax
    //
    //
    // Reverse-path   = Path / "<>"
    //
    // Forward-path   = Path
    //
    // Path           = "<" [ A-d-l ":" ] Mailbox ">"
    //
    // A-d-l          = At-domain *( "," At-domain )
    //                ; Note that this form, the so-called "source
    //                ; route", MUST BE accepted, SHOULD NOT be
    //                ; generated, and SHOULD be ignored.
    //
    // At-domain      = "@" Domain
    //
    // Mail-parameters  = esmtp-param *(SP esmtp-param)
    //
    // Rcpt-parameters  = esmtp-param *(SP esmtp-param)
    //
    // esmtp-param    = esmtp-keyword ["=" esmtp-value]
    //
    // esmtp-keyword  = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
    //
    // esmtp-value    = 1*(%d33-60 / %d62-126)
    //                ; any CHAR excluding "=", SP, and control
    //                ; characters.  If this string is an email address,
    //                ; i.e., a Mailbox, then the "xtext" syntax [32]
    //                ; SHOULD be used.
    //
    // Keyword        = Ldh-str
    //
    // Argument       = Atom
    //
    // Domain         = sub-domain *("." sub-domain)
    //
    // sub-domain     = Let-dig [Ldh-str]
    //
    // Let-dig        = ALPHA / DIGIT
    //
    // Ldh-str        = *( ALPHA / DIGIT / "-" ) Let-dig
    //
    // address-literal  = "[" ( IPv4-address-literal /
    //                  IPv6-address-literal /
    //                  General-address-literal ) "]"
    //                  ; See Section 4.1.3
    //
    // Mailbox        = Local-part "@" ( Domain / address-literal )
    //
    // Local-part     = Dot-string / Quoted-string
    //                ; MAY be case-sensitive
    //
    //
    // Dot-string     = Atom *("."  Atom)
    //
    // Atom           = 1*atext
    //
    // Quoted-string  = DQUOTE *QcontentSMTP DQUOTE
    //
    // QcontentSMTP   = qtextSMTP / quoted-pairSMTP
    //
    // quoted-pairSMTP  = %d92 %d32-126
    //                  ; i.e., backslash followed by any ASCII
    //                  ; graphic (including itself) or SPace
    //
    // qtextSMTP      = %d32-33 / %d35-91 / %d93-126
    //                ; i.e., within a quoted string, any
    //                ; ASCII graphic or space is permitted
    //                ; without blackslash-quoting except
    //                ; double-quote and the backslash itself.
    //
    // String         = Atom / Quoted-string
    //
    // See https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1.2
    static ref QTEXT_INTL: Regex = Regex::new(r"[\u0020-\u007E\u0080-\u{10FFFF}]").unwrap();
}

const MAX_ADDRESS_LENGTH: usize = 254;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_LOCAL_PART_LENGTH: usize = 64;
const MAX_DNS_LABEL_LENGTH: usize = 63;

create_exception!(emv, SyntaxError, PyValueError);
create_exception!(emv, DomainLiteralError, PyValueError);
create_exception!(emv, LengthError, PyValueError);

#[derive(Debug, Clone)]
#[pyclass]
pub struct ValidatedDomain {
    #[pyo3(get)]
    address: Option<IpAddr>,
    #[pyo3(get)]
    name: String,
}

#[derive(Debug)]
#[pyclass]
pub struct ValidatedEmail {
    #[pyo3(get)]
    pub local_part: String,
    #[pyo3(get)]
    pub domain: ValidatedDomain,
    #[pyo3(get)]
    pub is_valid: bool,
}

#[derive(Debug)]
pub struct EmailParts {
    pub local_part: String,
    pub domain: String,
}

#[derive(Debug, Default)]
#[pyclass]
pub struct EmailValidator {
    allow_smtputf8: bool,
    allow_empty_local: bool,
    allow_quoted_local: bool,
    allow_domain_literal: bool,
    // allow_display_name: bool,
    // check_deliverability: bool,
    // globally_deliverable: bool,
    // timeout: Option<u64>,
}

#[pymethods]
impl EmailValidator {
    #[new]
    #[pyo3(signature = (
        allow_smtputf8 = true,
        allow_empty_local = false,
        allow_quoted_local = false,
        allow_domain_literal = false
    ))]
    pub fn new(
        allow_smtputf8: bool,
        allow_empty_local: bool,
        allow_quoted_local: bool,
        allow_domain_literal: bool,
    ) -> Self {
        EmailValidator {
            allow_smtputf8,
            allow_empty_local,
            allow_quoted_local,
            allow_domain_literal,
        }
    }

    pub fn email(&self, email: &str) -> PyResult<ValidatedEmail> {
        let parts = split_email(&email)?;
        let local_part = parts.local_part;
        let udomain = parts.domain; // unvalidated domain

        // Validate length
        validate_length(&local_part, &udomain)?;

        // Validate local part
        let vlocal = self.local_part(&local_part)?;

        // Validate domain
        let vdomain = self.domain(&udomain)?;

        Ok(ValidatedEmail {
            local_part: vlocal,
            domain: vdomain,
            is_valid: true,
        })
    }

    pub fn local_part(&self, local: &str) -> PyResult<String> {
        // Guard clause if local_part is being executed independently
        if local.is_empty() {
            if !self.allow_empty_local {
                return Err(SyntaxError::new_err(
                    "There needs to be something before the the @-sign",
                ));
            }

            // Allowing empty local part.
            return Ok(local.to_string());
        }

        // Remove Surrounding quotes, unescaping any escaped characters within quotes.
        // Assuming that quoted locals are allowed.
        // This will help with local-part validation.
        let unquoted_local = unquote_local_part(local, self.allow_quoted_local)?;

        // Local-part
        //
        // The maximum total length of a user name or other local-part is 64
        // octets.
        // See https://www.rfc-editor.org/rfc/rfc5321.html#section-4.5.3.1.1
        if unquoted_local.len() > MAX_LOCAL_PART_LENGTH {
            return Err(LengthError::new_err(
                "The email address is too long befoe the @-sign",
            ));
        }

        // Atom
        //
        // Some structured header fields consist of strings called atoms, which contain basic characters.
        // In some cases, these fields also allow periods within sequences of atoms, referred to as "dot-atom" tokens.
        // All local parts that match the Atom rule are also valid as a quoted string, so we can
        // return here and skip the rest of the validation
        // See https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3
        if DOT_ATOM_TEXT.is_match(unquoted_local.as_bytes()) {
            return Ok(unquoted_local);
        }

        // Extended Mailbox Address Syntax
        //
        // RFC 5321 defines the <Mailbox> syntax using only ASCII characters. This document extends it to support non-ASCII characters with these key changes:
        // - Updates the <Mailbox> ABNF rule for internationalized email addresses.
        // - Extends <sub-domain> to include UTF-8 strings conforming to IDNA definitions.
        // - Broadens <atext> to allow UTF-8 strings, excluding ASCII graphics or control characters.
        // See https://www.rfc-editor.org/rfc/rfc6531#section-3.3
        if DOT_ATOM_TEXT_INTL.is_match(unquoted_local.as_bytes()) {
            if !self.allow_smtputf8 {
                return Err(SyntaxError::new_err(
                    "Internationalized characters before the @-sign are not supported",
                ));
            }

            // Check for unsafe characters
            validate_chars(&unquoted_local, false)?;

            // Try encoding to UTF-8
            if let Err(_) = String::from_utf8(local.as_bytes().to_vec()) {
                return Err(SyntaxError::new_err(
                    "The email address contains an invalid character",
                ));
            }

            return Ok(unquoted_local.to_string());
        }
        // Check for quoted local part and if it's allowed using the original local part.
        else if local.starts_with('"') && local.ends_with('"') {
            // Check for invalid characters that are not permitted in quoted local parts
            // See https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1.2
            let bad_chars: HashSet<_> = local
                .chars()
                .filter(|&c| !QTEXT_INTL.is_match(c.to_string().as_bytes()))
                .collect();

            if !bad_chars.is_empty() {
                return Err(SyntaxError::new_err(
                    "The email address contains invalid characters in quotes before the @-sign",
                ));
            }

            // Check for non-ASCII range characters
            let bad_chars: HashSet<_> = local
                .chars()
                .filter(|&c| !(32..=126).contains(&(c as u32)))
                .collect();

            if !bad_chars.is_empty() {
                if !self.allow_smtputf8 {
                    return Err(SyntaxError::new_err(
                        "Internationalized characters before the @-sign are not supported",
                    ));
                }
            }

            // Check for unsafe characters
            validate_chars(&unquoted_local, true)?;

            // Try encoding to UTF-8
            if let Err(_) = String::from_utf8(local.as_bytes().to_vec()) {
                return Err(SyntaxError::new_err(
                    "The email address contains an invalid character",
                ));
            }

            return Ok(local.to_string());
        }

        // See https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3
        let bad_chars: HashSet<_> = unquoted_local
            .chars()
            .filter(|&c| !ATEXT_INTL_DOT_RE.is_match(c.to_string().as_bytes()))
            .collect();

        if !bad_chars.is_empty() {
            return Err(SyntaxError::new_err(
                "The email address contains invalid characters before the @-sign",
            ));
        }

        // Check for dot errors
        if unquoted_local.starts_with('.')
            || unquoted_local.ends_with('.')
            || unquoted_local.contains("..")
        {
            return Err(SyntaxError::new_err(
                "The local part of the email address cannot start or end with a dot, or contain consecutive dots"
            ));
        }

        // We've exhuasted all validation clauses. Fallback error.
        Err(SyntaxError::new_err(
            "The email address contains invalid characters before the @-sign.",
        ))
    }

    pub fn domain(&self, domain: &str) -> PyResult<ValidatedDomain> {
        if domain.is_empty() {
            return Err(SyntaxError::new_err(
                "There needs to be something after the @".to_string(),
            ));
        }

        // Address Literals
        //
        // If a host is not recognized by the DNS, special address forms can be used.
        // For IPv4, this is four decimal numbers in brackets (e.g., [123.255.37.2]).
        // For IPv6, it includes a tag and the address (e.g., per RFC 4291).
        // See https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1.3
        if domain.starts_with('[') && domain.ends_with(']') {
            if !self.allow_domain_literal {
                return Err(DomainLiteralError::new_err(
                    "Domain Literals are not allowed".to_string(),
                ));
            }

            let domain_literal = &domain[1..domain.len() - 1];

            // Handle IPv6 addresses
            if domain_literal.starts_with("IPv6:") {
                let ipv6_literal = &domain_literal[5..];
                let addr = IpAddr::from_str(ipv6_literal).map_err(|_| {
                    SyntaxError::new_err(
                        "The IPv6 address in brackets after the @-sign is not valid.".to_string(),
                    )
                })?;
                if let IpAddr::V6(addr) = addr {
                    let normalized_name = format!("[IPv6:{}]", addr);
                    return Ok(ValidatedDomain {
                        name: normalized_name,
                        address: Some(IpAddr::V6(addr)),
                    });
                }
            }

            // Try to parse the domain literal as an IP address (either IPv4 or IPv6)
            let addr = IpAddr::from_str(domain_literal)
                .map_err(|_| SyntaxError::new_err("Invalid domain literal".to_string()))?;

            let normalized_name = match addr {
                IpAddr::V4(_) => format!("[{}]", addr),
                IpAddr::V6(_) => format!("[IPv6:{}]", addr),
            };

            return Ok(ValidatedDomain {
                name: normalized_name,
                address: Some(addr),
            });
        }

        // Check for invalid characters in the domain part
        if !ATEXT_HOSTNAME_INTL.is_match(domain.as_bytes()) {
            return Err(SyntaxError::new_err(
                "The part after the @-sign contains invalid characters.".to_string(),
            ));
        }

        // Check for unsafe characters
        validate_chars(&domain, false)?;

        // Normalize the domain using UTS-46
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
        if !ATEXT_HOSTNAME_INTL.is_match(normalized_domain.as_bytes()) {
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
        if normalized_domain.len() > MAX_DOMAIN_LENGTH {
            return Err(LengthError::new_err("The domain is too long".to_string()));
        }

        Ok(ValidatedDomain {
            name: normalized_domain.to_string(),
            address: None,
        })
    }
}

fn unquote_local_part(local: &str, allow_quoted: bool) -> Result<String, PyErr> {
    if local.starts_with('"') && local.ends_with('"') {
        // Check that the quoted local part is allowed, otherwise raise exception
        if !allow_quoted {
            return Err(SyntaxError::new_err(
                "Quoting the part before the @-sign is not allowed here.",
            ));
        }

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

    Ok(EmailParts {
        local_part: local_part.to_string(),
        domain: domain_part.to_string(),
    })
}

fn validate_length(local_part: &str, domain: &str) -> Result<(), PyErr> {
    if local_part.len() + domain.len() + 1 > MAX_ADDRESS_LENGTH {
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
        let validate = EmailValidator::default();

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
        let mut validate = EmailValidator::default();
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

        // Validate with domain literals
        let validate_with_domain_literal = EmailValidator {
            allow_domain_literal: true,
            ..EmailValidator::default()
        };

        let validated_email = validate_with_domain_literal
            .email("me@[127.0.0.1]")
            .unwrap();

        assert_eq!(validated_email.domain.name, "[127.0.0.1]");
        assert!(
            matches!(validated_email.domain.address, Some(IpAddr::V4(_))),
            "Expected an IPv4 address"
        );

        // Check if the address is of type IPv4
        if let Some(IpAddr::V4(addr)) = validated_email.domain.address {
            assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
        }

        // Check parsing IPv6 addresses
        let validated_email = validate_with_domain_literal.email("me@[IPv6:::1]").unwrap();
        assert_eq!(validated_email.domain.name, "[IPv6:::1]");
        assert!(
            matches!(validated_email.domain.address, Some(IpAddr::V6(_))),
            "Expected an IPv6 address"
        );
        if let Some(IpAddr::V6(addr)) = validated_email.domain.address {
            assert_eq!(addr, Ipv6Addr::from_str("::1").unwrap());
        }

        // Check that IPv6 addresses are normalized
        let validated_email = validate_with_domain_literal
            .email("me@[IPv6:0000:0000:0000:0000:0000:0000:0000:0001]")
            .unwrap();
        assert_eq!(validated_email.domain.name, "[IPv6:::1]");
        assert!(
            matches!(validated_email.domain.address, Some(IpAddr::V6(_))),
            "Expected an IPv6 address"
        );
        if let Some(IpAddr::V6(addr)) = validated_email.domain.address {
            assert_eq!(addr, Ipv6Addr::from_str("::1").unwrap());
        }
    }

    #[test]
    fn test_validate_local_part() {
        let validate = EmailValidator::default();

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
        let long_local_part = "a".repeat(MAX_LOCAL_PART_LENGTH + 1);
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
            ..EmailValidator::default()
        };

        // assert!(validate_with_smtputf8.local_part("用户").is_ok());
        // assert!(validate_with_smtputf8.local_part("θσερ").is_ok());
        // assert!(validate_with_smtputf8.local_part("коля").is_ok());
        // assert!(validate_with_smtputf8.local_part("δοκιμή").is_ok());
        // assert!(validate_with_smtputf8.local_part("üsername").is_ok());

        // Valid internationalized local parts
        let validate_no_smtputf8 = EmailValidator {
            allow_smtputf8: false,
            ..EmailValidator::default()
        };

        assert!(validate_no_smtputf8.local_part("üsername").is_err());
        // Invalid local parts - quoted local parts with invalid characters
        assert!(validate.local_part("\"user@name\"").is_err());
        assert!(validate.local_part("\"user\nname\"").is_err());
        assert!(validate.local_part("\"user\rname\"").is_err());
        assert!(validate
            .local_part("\"unnecessarily.quoted.local.part\"")
            .is_err());

        // Valid quoted local parts
        let validate_with_quoted = EmailValidator {
            allow_quoted_local: true,
            allow_smtputf8: true,
            ..EmailValidator::default()
        };

        assert!(validate_with_quoted.local_part("\"user name\"").is_ok());
        assert!(validate_with_quoted.local_part("\"user@name\"").is_ok());
        assert!(validate_with_quoted.local_part("\"user.name\"").is_ok());
        assert!(validate_with_quoted.local_part("\"user+name\"").is_ok());
        assert!(validate_with_quoted.local_part("\"user_name\"").is_ok());
        assert!(validate_with_quoted
            .local_part("\"quoted.with..unicode.λ\"")
            .is_ok());

        assert!(validate_with_quoted
            .local_part("\"unnecessarily.quoted.with.unicode.λ\"")
            .is_ok());
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
