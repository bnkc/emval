use pyo3::exceptions::{PySyntaxError, PyValueError};
use pyo3::prelude::*;

#[derive(Debug)]
pub enum ValidationError {
    SyntaxError(String),
    ValueError(String),
}

impl From<ValidationError> for PyErr {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::SyntaxError(msg) => PySyntaxError::new_err(msg),
            ValidationError::ValueError(msg) => PyValueError::new_err(msg),
        }
    }
}
