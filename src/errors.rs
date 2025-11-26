#[cfg(feature = "python")]
use pyo3::exceptions::{PySyntaxError, PyValueError};
#[cfg(feature = "python")]
use pyo3::prelude::*;

/// An error enum for email validation.
#[derive(Debug)]
pub enum ValidationError {
    /// A syntax error.
    SyntaxError(String),
    /// An error involving some input value.
    ValueError(String),
}

#[cfg(feature = "python")]
impl From<ValidationError> for PyErr {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::SyntaxError(msg) => PySyntaxError::new_err(msg),
            ValidationError::ValueError(msg) => PyValueError::new_err(msg),
        }
    }
}
