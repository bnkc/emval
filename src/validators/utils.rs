use crate::errors::ValidationError;
use std::collections::HashSet;
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

pub fn validate_email_label(
    label: &str,
    beg_descr: &str,
    end_descr: &str,
    is_hostname: bool,
) -> Result<(), ValidationError> {
    let errors = [
        (label.ends_with('.'), end_descr.replace("{}", "period")),
        (label.starts_with('.'), beg_descr.replace("{}", "period")),
        (
            label.contains(".."),
            "Invalid Email Address: Two periods ('.') cannot be adjacent in the email address.".to_string(),
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
            "Invalid Email Address: A period ('.') and a hyphen ('-') cannot be adjacent in the email address.".to_string(),
        ),
    ];

    for (condition, error) in errors.iter() {
        if *condition {
            return Err(ValidationError::SyntaxError(error.clone()));
        }
    }

    Ok(())
}

pub fn validate_email_length(local_part: &str, domain: &str) -> Result<(), ValidationError> {
    if local_part.len() + domain.len() + 1 > crate::consts::MAX_ADDRESS_LENGTH {
        return Err(ValidationError::ValueError(
            "Invalid Email Address: The email exceeds the maximum length (254 chars).".to_string(),
        ));
    }
    Ok(())
}

pub fn split_email(email: &str) -> Result<(String, String), ValidationError> {
    let at_pos = email.rfind('@').ok_or_else(|| {
        ValidationError::SyntaxError("Invalid Email Address: Missing an '@' sign.".to_string())
    })?;

    let local_part = &email[..at_pos];
    let domain_part = &email[at_pos + 1..];

    Ok((local_part.to_string(), domain_part.to_string()))
}

pub fn validate_chars(chars: &str, allow_space: bool) -> Result<(), ValidationError> {
    let mut bad_chars = HashSet::new();

    for (i, c) in chars.chars().enumerate() {
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
            .map(|c| display_char(*c))
            .collect::<Vec<_>>()
            .join(", ");

        return Err(ValidationError::SyntaxError(format!(
            "Invalid Email Address: contains invalid characters: {}.",
            bad_chars_str
        )));
    }

    Ok(())
}

fn display_char(c: char) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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
        let result = validate_chars(input, allow_space);

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
        let result = validate_chars(input, allow_space);

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
        let result = validate_chars(input, allow_space);

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
        let result = split_email(input);

        assert!(result.is_ok());
    }

    #[rstest]
    #[case("plainaddress")]
    #[case("missing-at-sign.com")]
    #[case("")]
    fn test_split_email_invalid(#[case] input: &str) {
        let result = split_email(input);

        assert!(result.is_err());
    }
}
