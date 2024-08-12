#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::arithmetic_side_effects,
    clippy::mod_module_files,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "std")]
extern crate std;

pub use cipher::{self, Cipher};
pub use encoding::{self, Decode, Encode, Reader, Writer};
pub use key::{
    self, certificate::Certificate, private::PrivateKey, public::PublicKey, Algorithm, Fingerprint,
    HashAlg, Kdf, KdfAlg, Signature,
};

use encoding::Error as EncodingError;

/// Error emitted by the ssh protocol
#[derive(Debug)]
pub enum Error {
    /// Encoding error
    Encoding(EncodingError),
}

impl From<EncodingError> for Error {
    fn from(e: EncodingError) -> Self {
        Self::Encoding(e)
    }
}

#[cfg(feature = "std")]
mod error_std {
    use super::Error;
    use std::{error, fmt};

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Encoding(e) => e.fmt(f),
            }
        }
    }

    impl error::Error for Error {}
}
