#![feature(ip)]
#[macro_use]
extern crate lazy_static;
pub(crate) mod consts;
pub(crate) mod errors;
pub(crate) mod models;
pub(crate) mod validators;
pub mod prelude {
    pub use crate::models::{EmailValidator, ValidatedEmail};
}

use pyo3::prelude::*;

#[pymodule]
fn _emval(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<models::EmailValidator>()?;
    m.add_class::<models::ValidatedEmail>()?;

    Ok(())
}
