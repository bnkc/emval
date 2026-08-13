use pyo3::exceptions::{PySyntaxError, PyValueError};
use pyo3::prelude::*;
use std::fmt;

/// An error enum for email validation.
#[derive(Debug)]
pub enum ValidationError {
    /// A syntax error.
    SyntaxError(String),
    /// An error involving some input value.
    ValueError(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::SyntaxError(message) | ValidationError::ValueError(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<ValidationError> for PyErr {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::SyntaxError(msg) => PySyntaxError::new_err(msg),
            ValidationError::ValueError(msg) => PyValueError::new_err(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_errors_display_their_python_message() {
        let message = "Invalid Email Address: Missing an '@' sign.";

        assert_eq!(
            ValidationError::SyntaxError(message.to_string()).to_string(),
            message
        );
        assert_eq!(
            ValidationError::ValueError(message.to_string()).to_string(),
            message
        );
    }
}
