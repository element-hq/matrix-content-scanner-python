use std::{
    borrow::Cow,
    fs,
    io::{Cursor, ErrorKind, Read},
};

use anyhow::{Context, Error};
use matrix_sdk_crypto::AttachmentDecryptor;
use pyo3::{
    prelude::*,
    types::{PyBytes, PyDict},
};
use pythonize::depythonize_bound;
use vodozemac::{
    base64_encode,
    pk_encryption::{self, PkDecryption},
    Curve25519PublicKey,
};

/// Called when registering modules with python.
pub fn register_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let child_module = PyModule::new_bound(py, "crypto")?;
    child_module.add_class::<CryptoHandler>()?;
    child_module.add_class::<PkMessage>()?;
    child_module.add_function(wrap_pyfunction!(decrypt_attachment, &child_module)?)?;

    m.add_submodule(&child_module)?;

    Ok(())
}

#[pyclass(frozen)]
pub struct CryptoHandler {
    decryptor: PkDecryption,
}

#[pymethods]
impl CryptoHandler {
    #[new]
    pub fn py_new(pickle_key: &str, pickle_path: &str) -> Result<Self, Error> {
        match fs::read_to_string(pickle_path) {
            Ok(pickle) => {
                let decryptor = PkDecryption::from_libolm_pickle(&pickle, pickle_key.as_bytes())?;

                log::info!("Loaded Olm key pair from pickle file {}", pickle_path);

                Ok(Self { decryptor })
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                log::info!(
                        "Pickle file not found, generating a new Olm key pair and storing it in pickle file {}",
                        pickle_path,
                    );

                let decryptor = PkDecryption::new();
                let pickle = decryptor.to_libolm_pickle(pickle_key.as_bytes())?;
                fs::write(pickle_path, pickle)?;
                Ok(Self { decryptor })
            }
            Err(e) => {
                Err(e).with_context(|| format!("Failed to read the pickle file at the location configured for crypto.pickle_path ({pickle_path})"))
            }
        }
    }

    #[getter]
    pub fn public_key(&self) -> String {
        self.decryptor.public_key().to_base64()
    }

    pub fn decrypt_body(
        &self,
        ciphertext: &str,
        mac: &str,
        ephemeral: &str,
    ) -> Result<String, Error> {
        let message = pk_encryption::Message::from_base64(ciphertext, mac, ephemeral)?;
        let decrypted = self.decryptor.decrypt(&message)?;
        let decrypted =
            String::from_utf8(decrypted).context("Decrypted message isn't valid UTF-8")?;
        Ok(decrypted)
    }

    pub fn encrypt(&self, public_key: &str, payload: &str) -> Result<PkMessage, Error> {
        let encryptor =
            pk_encryption::PkEncryption::from_key(Curve25519PublicKey::from_base64(public_key)?);
        Ok(PkMessage(encryptor.encrypt(payload.as_bytes())))
    }
}

#[pyclass(frozen)]
pub struct PkMessage(pk_encryption::Message);

#[pymethods]
impl PkMessage {
    #[getter]
    pub fn ephemeral_key(&self) -> String {
        self.0.ephemeral_key.to_base64()
    }

    #[getter]
    pub fn mac(&self) -> String {
        base64_encode(&self.0.mac)
    }

    #[getter]
    pub fn ciphertext(&self) -> String {
        base64_encode(&self.0.ciphertext)
    }
}

#[pyfunction]
pub fn decrypt_attachment(
    body: Bound<'_, PyBytes>,
    key_info: Bound<'_, PyDict>,
) -> Result<Cow<'static, [u8]>, Error> {
    let mut cursor = Cursor::new(body.as_bytes());
    let info =
        depythonize_bound(key_info.into_any()).context("Failed parsing supplied key info")?;

    let mut decryptor = AttachmentDecryptor::new(&mut cursor, info)?;
    let mut decrypted_data = Vec::new();

    decryptor.read_to_end(&mut decrypted_data)?;

    Ok(Cow::Owned(decrypted_data))
}
