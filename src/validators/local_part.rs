use crate::errors::ValidationError;
use crate::models::EmailValidator;
use std::collections::HashSet;

pub fn validate_local_part(
    validator: &EmailValidator,
    local: &str,
) -> Result<String, ValidationError> {
    if local.is_empty() {
        return if validator.allow_empty_local {
            Ok(local.to_string())
        } else {
            Err(ValidationError::SyntaxError(
                "Invalid Local Part: The part before the '@' sign cannot be empty.".to_string(),
            ))
        };
    }

    // Remove surrounding quotes, unescaping any escaped characters within quotes
    let unquoted_local = unquote_local_part(local, validator.allow_quoted_local)?;

    // Local part length validation
    if unquoted_local.len() > crate::consts::MAX_LOCAL_PART_LENGTH {
        return Err(ValidationError::ValueError(
            "Invalid Local Part: The part before the '@' sign exceeds the maximum length (64 chars).".to_string(),
        ));
    }

    // Check for valid dot-atom text
    if crate::consts::DOT_ATOM_TEXT.is_match(unquoted_local.as_bytes()) {
        return Ok(unquoted_local);
    }

    // Check for valid internationalized dot-atom text
    if crate::consts::DOT_ATOM_TEXT_INTL.is_match(unquoted_local.as_bytes()) {
        if !validator.allow_smtputf8 {
            return Err(ValidationError::SyntaxError(
                        "Invalid Local Part: Internationalized characters before the '@' sign are not supported.".to_string(),
                ));
        }
        crate::validators::validate_chars(&unquoted_local, false)?;

        // Check for valid UTF-8 encoding
        if String::from_utf8(unquoted_local.as_bytes().to_vec()).is_err() {
            return Err(ValidationError::SyntaxError(
                "Invalid Local Part: Contains non-UTF-8 characters.".to_string(),
            ));
        }

        return Ok(unquoted_local.to_string());
    }

    // Check for quoted local part and validate
    if local.starts_with('"') && local.ends_with('"') {
        let invalid_chars: HashSet<_> = local
            .chars()
            .filter(|&c| !crate::consts::QTEXT_INTL.is_match(c.to_string().as_bytes()))
            .collect();

        if !invalid_chars.is_empty() {
            return Err(ValidationError::SyntaxError(
                        "Invalid Local Part: contains invalid characters within quoted local part before the '@' sign.".to_string(),
                ));
        }

        let invalid_non_ascii_chars: HashSet<_> = local
            .chars()
            .filter(|&c| !(32..=126).contains(&(c as u32)))
            .collect();

        if !invalid_non_ascii_chars.is_empty() && !validator.allow_smtputf8 {
            return Err(ValidationError::SyntaxError(
                        "Invalid Local Part: Internationalized characters before the '@' sign are not supported.".to_string(),
                ));
        }

        crate::validators::validate_chars(&unquoted_local, true)?;

        // Check for valid UTF-8 encoding
        if String::from_utf8(local.as_bytes().to_vec()).is_err() {
            return Err(ValidationError::SyntaxError(
                "Invalid Local Part: Contains non-UTF-8 characters.".to_string(),
            ));
        }

        return Ok(local.to_string());
    }

    // Check for other invalid characters
    let invalid_chars: HashSet<_> = unquoted_local
        .chars()
        .filter(|&c| !crate::consts::ATEXT_INTL_DOT_RE.is_match(c.to_string().as_bytes()))
        .collect();

    if !invalid_chars.is_empty() {
        return Err(ValidationError::SyntaxError(
            "Invalid Local Part: contains invalid characters before the '@' sign.".to_string(),
        ));
    }

    // Validates the local part of an email address based on RFC 952, RFC 1123, and RFC 5322.
    // Each label must have at least one character and cannot start or end with dashes or periods.
    // Consecutive periods and adjacent period-hyphen combinations are also invalid.
    crate::validators::validate_email_label(
        local,
        "Invalid Local Part: Cannot start with a {}.",
        "Invalid Local Part: A {} cannot immediately precede the '@' sign.",
        true,
    )?;

    Err(ValidationError::SyntaxError(
        "Invalid Local Part: contains invalid characters before the '@' sign.".to_string(),
    ))
}

fn unquote_local_part(local: &str, allow_quoted: bool) -> Result<String, ValidationError> {
    if local.starts_with('"') && local.ends_with('"') {
        // Check that the quoted local part is allowed, otherwise raise exception
        if !allow_quoted {
            return Err(ValidationError::SyntaxError(
                "Invalid Local Part: Quoting the local part before the '@' sign is not permitted in this context.".to_string(),
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
            return Err(ValidationError::SyntaxError(
                "Invalid Local Part: Trailing escape character in the quoted local part before the '@' sign.".to_string(),
            ));
        }

        Ok(unquoted)
    } else {
        Ok(local.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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
        let emval = EmailValidator {
            allow_quoted_local,
            allow_smtputf8,
            ..EmailValidator::default()
        };

        let result = validate_local_part(&emval, input);

        if let Some(expected_local) = expected {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_local);
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case("", None, false, true)]
    #[case(&"a".repeat(crate::consts::MAX_LOCAL_PART_LENGTH + 1), None, false, true)]
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
        let emval = EmailValidator {
            allow_quoted_local,
            allow_smtputf8,
            ..EmailValidator::default()
        };

        let result = validate_local_part(&emval, input);

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
        let emval = EmailValidator {
            allow_quoted_local,
            allow_smtputf8,
            ..EmailValidator::default()
        };

        let result = validate_local_part(&emval, input);

        if let Some(expected_local) = expected {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_local);
        } else {
            assert!(result.is_err());
        }
    }
}
