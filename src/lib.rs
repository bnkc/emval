#![feature(ip)]
#[macro_use]
extern crate lazy_static;
mod consts;
pub mod errors;
mod models;
mod validators;

pub use crate::errors::ValidationError;
pub use crate::models::{EmailValidator, ValidatedEmail};

use pyo3::prelude::*;

#[pymodule]
fn _emval(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<models::EmailValidator>()?;
    m.add_class::<models::ValidatedEmail>()?;

    Ok(())
}
