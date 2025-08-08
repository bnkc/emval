#![feature(ip)]
#[macro_use]
extern crate lazy_static;
mod consts;
mod errors;
mod models;
mod validators;
mod polars_plugin;

use pyo3::prelude::*;

#[pymodule]
fn _emval(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<models::EmailValidator>()?;
    m.add_class::<models::ValidatedEmail>()?;

    Ok(())
}
