use std::usize;

use regex::bytes::Regex;

lazy_static! {
    // See https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3
    pub static ref ATEXT: &'static str = r"a-zA-Z0-9_!#\$%&'\*\+\-/=\?\^`\{\|\}~";
    pub static ref ATEXT_RE: Regex = Regex::new(&format!(r"[.{}]", *ATEXT)).unwrap();
    pub static ref DOT_ATOM_TEXT: Regex = Regex::new(&format!(r"^[{}]+(?:\.[{}]+)*$", *ATEXT, *ATEXT)).unwrap();

    // RFC 6531 3.3 extends allowed characters in internationalized addresses
    static ref ATEXT_INTL: String = format!("{}{}", *ATEXT, r"\u{0080}-\u{10FFFF}");
    pub static ref ATEXT_INTL_DOT_RE: Regex = Regex::new(&format!(r"[.{}]", *ATEXT_INTL)).unwrap();
    pub static ref DOT_ATOM_TEXT_INTL: Regex =
        Regex::new(&format!(r"^[{}]+(?:\.[{}]+)*$", *ATEXT_INTL, *ATEXT_INTL)).unwrap();

    // The domain part of the email address, after IDNA (ASCII) encoding,
    // must also satisfy the requirements of RFC 952/RFC 1123 2.1
    pub static ref ATEXT_HOSTNAME_INTL: Regex = Regex::new(r"^[a-zA-Z0-9\-\.\u{0080}-\u{10FFFF}]+$").unwrap();
    pub static ref HOSTNAME_LABEL: &'static str = r"(?:(?:[a-zA-Z0-9][a-zA-Z0-9\-]*)?[a-zA-Z0-9])";
    pub static ref DOT_ATOM_TEXT_HOSTNAME: Regex =
        Regex::new(&format!(r"^{}(?:\.{})*$", *HOSTNAME_LABEL, *HOSTNAME_LABEL)).unwrap();
    pub static ref DOMAIN_NAME_REGEX: Regex = Regex::new(r"[A-Za-z]\z").unwrap();

    // Domain literal (RFC 5322 3.4.1)
    pub static ref DOMAIN_LITERAL_CHARS: Regex = Regex::new(r"[\u0021-\u00FA\u005E-\u007E]").unwrap();

    // See https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1.2
    pub static ref QTEXT_INTL: Regex = Regex::new(r"[\u0020-\u007E\u0080-\u{10FFFF}]").unwrap();
    pub static ref DNS_LABEL_REGEX: Regex = Regex::new(r"(?i)^.{2}--").unwrap();
}

pub const MAX_ADDRESS_LENGTH: usize = 254;
pub const MAX_DOMAIN_LENGTH: usize = 253;
pub const MAX_LOCAL_PART_LENGTH: usize = 64;
pub const MAX_DNS_LABEL_LENGTH: usize = 63;
pub const SPECIAL_USE_DOMAIN_NAMES: &[&str] =
    &["arpa", "invalid", "local", "localhost", "onion", "test"];
pub const CASE_INSENSITIVE_MAILBOX_NAMES: &[&str] = &[
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
