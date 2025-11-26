use crate::errors::ValidationError;
use crate::models::EmailValidator;
use idna::uts46::Uts46;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens};
use std::net::IpAddr;
use std::str::FromStr;
#[cfg(feature = "dns")]
use trust_dns_resolver::config::*;
#[cfg(feature = "dns")]
use trust_dns_resolver::Resolver;
#[cfg(feature = "dns")]
use crate::util::ip_addr_ext::IpAddrExt;

pub fn validate_domain(
    validator: &EmailValidator,
    domain: &str,
) -> Result<(String, String, Option<IpAddr>, bool), ValidationError> {
    // Guard clause if domain is being executed independently
    if domain.is_empty() {
        return Err(ValidationError::SyntaxError(
            "Invalid Domain: The part after the '@' sign cannot be empty.".to_string(),
        ));
    }

    // Address Literals
    if domain.starts_with('[') && domain.ends_with(']') {
        if !validator.allow_domain_literal {
            return Err(ValidationError::ValueError(
                "Invalid Domain: A bracketed IP address after the '@' sign is not permitted."
                    .to_string(),
            ));
        }

        let domain_literal = &domain[1..domain.len() - 1];

        // Handle IPv6 addresses
        if domain_literal.starts_with("IPv6:") {
            let ipv6_literal = &domain_literal[5..];
            let addr = IpAddr::from_str(ipv6_literal).map_err(|_| {
                    ValidationError::SyntaxError(
                        "Invalid Domain: The IPv6 address in brackets following the '@' symbol is not valid."
                            .to_string(),
                    )
                })?;
            if let IpAddr::V6(addr) = addr {
                let name = format!("[IPv6:{}]", addr);
                return Ok((name.clone(), name, Some(IpAddr::V6(addr)), false));
            }
        }

        // Try to parse the domain literal as an IP address (either IPv4 or IPv6)
        let addr = IpAddr::from_str(domain_literal).map_err(|_| {
                 ValidationError::SyntaxError(
                    "Invalid Domain: The address in brackets following the '@' sign is not a valid IP address."
                        .to_string(),
                )
            })?;

        let name = match addr {
            IpAddr::V4(_) => format!("[{}]", addr),
            IpAddr::V6(_) => format!("[IPv6:{}]", addr),
        };

        return Ok((name.clone(), name, Some(addr), false));
    }

    // Check for invalid characters in the domain part
    if !crate::consts::ATEXT_HOSTNAME_INTL.is_match(domain.as_bytes()) {
        return Err(ValidationError::SyntaxError(
            "Invalid Domain: Contains invalid characters after '@' sign.".to_string(),
        ));
    }

    // Check for unsafe characters
    crate::validators::validate_chars(domain, false)?;

    // Normalize the domain using UTS-46
    let ascii_domain = Uts46::new()
            .to_ascii(
                domain.as_bytes(),
                AsciiDenyList::URL,
                Hyphens::Allow,
                DnsLength::Verify,
            )
            .map_err(|_| {
                ValidationError::SyntaxError(
                    "Invalid Domain: Contains invalid characters after '@' sign post Unicode normalization."
                        .to_string(),
                )
            })?;

    // Check for invalid chars after normalization
    if !crate::consts::ATEXT_HOSTNAME_INTL.is_match(ascii_domain.as_bytes()) {
        return Err(ValidationError::SyntaxError(
            "Invalid Domain: Contains invalid characters after Unicode normalization.".to_string(),
        ));
    }

    // Validates the domain part of an email address based on RFC 952, RFC 1123, and RFC 5322.
    // Each label must have at least one character and cannot start or end with dashes or periods.
    // Consecutive periods and adjacent period-hyphen combinations are also invalid.
    crate::validators::validate_email_label(
        &ascii_domain,
        "Invalid Domain: A {} cannot immediately follow the '@' symbol.",
        "Invalid Domain: A {} cannot appear at the end of the domain.",
        true,
    )?;

    // Check the total length of the domain
    if ascii_domain.len() > crate::consts::MAX_DOMAIN_LENGTH {
        return Err(ValidationError::ValueError(
            "Invalid Domain: Exceeds the maximum length (253 chars).".to_string(),
        ));
    }

    // Check for invalid domain labels
    for label in ascii_domain.split('.') {
        if label.len() > crate::consts::MAX_DNS_LABEL_LENGTH {
            return Err(ValidationError::ValueError(
                "Invalid Label: Exceeds the maximum length (63 chars).".to_string(),
            ));
        }

        if label.is_empty() {
            return Err(ValidationError::SyntaxError(
                "Invalid Label: The Label cannot be empty.".to_string(),
            ));
        }

        // Check for two letters followed by two dashes
        if crate::consts::DNS_LABEL_REGEX.is_match(label.as_bytes())
            && !label.to_lowercase().starts_with("xn--")
        {
            return Err(ValidationError::SyntaxError(
                     "Invalid Domain: Two letters followed by two dashes ('--') are not allowed immediately after the '@' sign or a period.".to_string(),
             ));
        }
    }

    if validator.deliverable_address {
        // Deliverable addresses must contain atleast one period.
        if !ascii_domain.contains(".") {
            return Err(ValidationError::SyntaxError(
                "Invalid Domain: Must contain a period ('.') to be considered valid.".to_string(),
            ));
        }

        // TLDs must end with a letter.
        if !crate::consts::DOMAIN_NAME_REGEX.is_match(ascii_domain.as_bytes()) {
            return Err(ValidationError::SyntaxError(
                    "Invalid domain: The part after the '@' sign does not belong to a valid top-level domain (TLD).".to_string(),
                ));
        }
    }

    let (unicode_domain, result) =
        Uts46::new().to_unicode(ascii_domain.as_bytes(), AsciiDenyList::URL, Hyphens::Allow);
    result.map_err(|_| {
        ValidationError::SyntaxError("Invalid Domain: Contains invalid characters after '@' sign post Unicode normalization.".to_string())
    })?;

    let maybe_special_domain =
        crate::consts::SPECIAL_USE_DOMAIN_NAMES
            .iter()
            .find(|special_domain| {
                ascii_domain == **special_domain
                    || ascii_domain.ends_with(&format!(".{}", special_domain))
            });

    if let Some(special) = maybe_special_domain {
        // Check if this special domain is in the allowed list
        let is_allowed = validator
            .allowed_special_domains
            .iter()
            .any(|allowed| allowed == special);

        if !is_allowed {
            Err(ValidationError::SyntaxError(
                        "Invalid Domain: The part after the '@' sign is a reserved or special-use domain that cannot be used.".to_string(),
                ))
        } else {
            Ok((
                unicode_domain.to_string(),
                ascii_domain.to_string(),
                None,
                true,
            ))
        }
    } else {
        Ok((
            unicode_domain.to_string(),
            ascii_domain.to_string(),
            None,
            false,
        ))
    }
}

#[cfg(feature = "dns")]
pub fn validate_deliverability(domain: &str) -> Result<(), ValidationError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|e| ValidationError::SyntaxError(e.to_string()))?;

    // Check MX records
    if let Ok(mx_records) = resolver.mx_lookup(domain) {
        for mx in mx_records.iter() {
            let exchange = mx.exchange().to_string();
            if exchange == "." {
                return Err(ValidationError::SyntaxError(
                    "Invalid Domain: The domain does not accept email due to a null MX record, indicating it is not configured to receive emails.".to_string(),
                ));
            }
        }
        if mx_records
            .iter()
            .any(|mx| !mx.exchange().to_string().is_empty())
        {
            return Ok(());
        }
    }

    // Fallback to A/AAAA records
    if let Ok(a_records) = resolver.ipv4_lookup(domain) {
        if a_records.iter().any(|ip| IpAddrExt::is_global(&ip.0)) {
            return Ok(());
        }
    }
    if let Ok(aaaa_records) = resolver.ipv6_lookup(domain) {
        if aaaa_records.iter().any(|ip| IpAddrExt::is_global(&ip.0)) {
            return Ok(());
        }
    }

    // Check SPF records (TXT)
    if let Ok(txt_records) = resolver.txt_lookup(domain) {
        for record in txt_records.iter() {
            let txt = record.to_string();
            if txt.starts_with("v=spf1 ") && txt.contains("-all") {
                return Err(ValidationError::SyntaxError(
                    "Invalid Domain: The domain does not send email due to an SPF record that rejects all emails.".to_string(),
                ));
            }
        }
    }

    Err(ValidationError::SyntaxError(
        "Invalid Domain: No MX, A, or AAAA records found for domain.".to_string(),
    ))
}

#[cfg(not(feature = "dns"))]
pub fn validate_deliverability(_domain: &str) -> Result<(), ValidationError> {
    // DNS resolution is not available when dns feature is disabled
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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
        let emval = EmailValidator::default();
        let result = validate_domain(&emval, domain);

        assert!(result.is_ok());
    }

    #[rstest]
    fn test_validate_domain_idna() {
        let emval = EmailValidator::default();
        let result = validate_domain(&emval, "xn--fsqu00a.xn--4rr70v");
        assert_eq!(
            result.unwrap(),
            (
                "例子.广告".to_string(),
                "xn--fsqu00a.xn--4rr70v".to_string(),
                None,
                false
            )
        );
        let result = validate_domain(&emval, "例子.广告");
        assert_eq!(
            result.unwrap(),
            (
                "例子.广告".to_string(),
                "xn--fsqu00a.xn--4rr70v".to_string(),
                None,
                false
            )
        );
    }

    #[rstest]
    #[case("invali*d.com")]
    #[case(&"a".repeat(64))]
    #[case("a.com-")]
    #[case("a-.com")]
    #[case(&(String::from("a") + &".com".repeat(126)))]
    #[case("example..com")] // Double dot
    #[case("example-.com")] // Trailing hyphen
    #[case("example-.com")] // Leading hyphen
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
        let emval = EmailValidator::default();
        let result = validate_domain(&emval, domain);

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
        let emval = EmailValidator::default();
        let result = validate_domain(&emval, domain);

        if expected {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case("null.example.com")]
    #[case("nonexistentdomain.example")]
    #[case("-invaliddomain.com")]
    #[case("invalid_domain.com")]
    #[case("例え.テスト")]
    #[case("example..com")]
    fn test_validate_deliverability_invalid(#[case] domain: &str) {
        assert!(validate_deliverability(domain).is_err());
    }

    #[rstest]
    #[case("google.com")]
    #[case("gmail.com")]
    #[case("yahoo.com")]
    #[case("hotmail.com")]
    #[case("outlook.com")]
    #[case("aol.com")]
    fn test_validate_deliverability_valid(#[case] domain: &str) {
        assert!(validate_deliverability(domain).is_ok());
    }

    #[rstest]
    #[case("blackhole.isi.edu")] // Known to have a null MX record
    fn test_validate_deliverability_null_mx(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("www.cloudflare.com")]
    #[case("osu.edu")] // OSU's domain
    fn test_validate_deliverability_valid_a_no_mx(#[case] domain: &str) {
        assert!(validate_deliverability(domain).is_ok());
    }

    #[rstest]
    #[case("nonexistentdomain.example")]
    #[case("invalid-domain-test-12345.com")]
    fn test_validate_deliverability_no_records(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("thisdomaindoesnotexist.tld")]
    fn test_validate_deliverability_nxdomain(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        assert!(result.is_err());
    }
    #[rstest]
    #[case("example.com")]
    #[case("example.org")]
    fn test_validate_deliverability_spf_reject_all(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("localhost")] // Resolves to 127.0.0.1
    #[case("example.internal")] // Assuming it resolves to a private IP
    fn test_validate_deliverability_private_ip(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("-invaliddomain.com")]
    #[case("invalid_domain.com")]
    #[case("example..com")]
    fn test_validate_deliverability_invalid_syntax(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("例え.テスト")] // Japanese IDN for "example.test"
    #[case("مثال.إختبار")] // Arabic IDN for "example.test"
    fn test_validate_deliverability_idn(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        // Depending on the domain, it may pass or fail
        // We're checking that the function handles IDNs without panicking
        assert!(result.is_err() || result.is_ok());
    }

    #[rstest]
    #[case("no-ns.example.com")] // Assuming this domain has no nameservers
    fn test_validate_deliverability_no_nameservers(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        // Depending on implementation, might return an error or a specific message
        assert!(result.is_err());
    }

    #[rstest]
    #[case("timeout.example.com")]
    fn test_validate_deliverability_timeout(#[case] domain: &str) {
        let result = validate_deliverability(domain);
        // Should handle timeout gracefully
        assert!(result.is_err());
    }
}
