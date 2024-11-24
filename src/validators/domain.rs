use crate::errors::ValidationError;
use crate::models::EmailValidator;
use idna::uts46::Uts46;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens};
use std::net::IpAddr;
use std::str::FromStr;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

pub fn validate_domain(
    validator: &EmailValidator,
    domain: &str,
) -> Result<(String, Option<IpAddr>), ValidationError> {
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
                return Ok((format!("[IPv6:{}]", addr), Some(IpAddr::V6(addr))));
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

        return Ok((name, Some(addr)));
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
    let normalized_domain = Uts46::new()
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
    if !crate::consts::ATEXT_HOSTNAME_INTL.is_match(normalized_domain.as_bytes()) {
        return Err(ValidationError::SyntaxError(
            "Invalid Domain: Contains invalid characters after Unicode normalization.".to_string(),
        ));
    }

    // Validates the domain part of an email address based on RFC 952, RFC 1123, and RFC 5322.
    // Each label must have at least one character and cannot start or end with dashes or periods.
    // Consecutive periods and adjacent period-hyphen combinations are also invalid.
    crate::validators::validate_email_label(
        &normalized_domain,
        "Invalid Domain: A {} cannot immediately follow the '@' symbol.",
        "Invalid Domain: A {} cannot appear at the end of the domain.",
        true,
    )?;

    // Check the total length of the domain
    if normalized_domain.len() > crate::consts::MAX_DOMAIN_LENGTH {
        return Err(ValidationError::ValueError(
            "Invalid Domain: Exceeds the maximum length (253 chars).".to_string(),
        ));
    }

    // Check for invalid domain labels
    for label in normalized_domain.split('.') {
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
        if !normalized_domain.contains(".") {
            return Err(ValidationError::SyntaxError(
                "Invalid Domain: Must contain a period ('.') to be considered valid.".to_string(),
            ));
        }

        // TLDs must end with a letter.
        if !crate::consts::DOMAIN_NAME_REGEX.is_match(normalized_domain.as_bytes()) {
            return Err(ValidationError::SyntaxError(
                    "Invalid domain: The part after the '@' sign does not belong to a valid top-level domain (TLD).".to_string(),
                ));
        }
    }

    // Check for reserved and "special use" domains
    for &special_domain in crate::consts::SPECIAL_USE_DOMAIN_NAMES {
        if normalized_domain == special_domain
            || normalized_domain.ends_with(&format!(".{}", special_domain))
        {
            return Err(ValidationError::SyntaxError(
                    "Invalid Domain: The part after the '@' sign is a reserved or special-use domain that cannot be used.".to_string(),
            ));
        }
    }
    Ok((normalized_domain.to_string(), None))
}

fn resolve_mx_records(domain: &str) -> Result<(), ValidationError> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|e| ValidationError::SyntaxError(e.to_string()))?;

    let mx_records = resolver.mx_lookup(domain).map_err(|_| {
        ValidationError::SyntaxError("Failed to resolve MX records for the domain.".to_string())
    })?;

    // Filter out null MX records from the list. Null MX records are identified by an empty
    // 'exchange' field, which occurs after trailing dots have been stripped. This ensures
    // that we only consider non-null MX records when determining the validity of the domain.
    if mx_records
        .iter()
        .all(|mx| mx.exchange().to_string().is_empty())
    {
        return Err(ValidationError::SyntaxError(
            "No MX records found for the domain.".to_string(),
        ));
    }
    Ok(())
}

fn resolve_fallback_records(domain: &str) -> Result<(), ValidationError> {
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
    fn test_mx_lookup_invalid(#[case] domain: &str) {
        assert!(resolve_mx_records(domain).is_err());
    }

    #[rstest]
    #[case("google.com")]
    #[case("gmail.com")]
    #[case("yahoo.com")]
    #[case("hotmail.com")]
    #[case("outlook.com")]
    #[case("aol.com")]
    fn test_mx_lookup_valid(#[case] domain: &str) {
        assert!(resolve_mx_records(domain).is_ok());
    }
}
