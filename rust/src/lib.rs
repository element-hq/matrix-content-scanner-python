use lazy_static::lazy_static;
use pyo3::prelude::*;
use pyo3_log::ResetHandle;

pub mod crypto;

lazy_static! {
    static ref LOGGING_HANDLE: ResetHandle = pyo3_log::init();
}

/// Returns the hash of all the rust source files at the time it was compiled.
///
/// Used by python to detect if the rust library is outdated.
#[pyfunction]
fn get_rust_file_digest() -> &'static str {
    env!("MCS_RUST_DIGEST")
}

/// Reset the cached logging configuration of pyo3-log to pick up any changes
/// in the Python logging configuration.
///
#[pyfunction]
fn reset_logging_config() {
    LOGGING_HANDLE.reset();
}

/// The entry point for defining the Python module.
#[pymodule]
fn mcs_rust(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_rust_file_digest, m)?)?;
    m.add_function(wrap_pyfunction!(reset_logging_config, m)?)?;

    crypto::register_module(py, m)?;

    Ok(())
}
