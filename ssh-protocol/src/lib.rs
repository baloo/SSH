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

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use cipher::{self, Cipher};
pub use encoding::{self, Decode, Encode, Reader, Writer};
pub use key::{
    self, certificate::Certificate, private::PrivateKey, public::PublicKey, Algorithm,
    Error as KeyError, Fingerprint, HashAlg, Kdf, KdfAlg, Signature,
};

use encoding::Error as EncodingError;

mod client_server;
pub mod codec;
pub mod constants;
mod cookie;
pub mod ecdh;
pub mod key_exchange;
mod name_list;
mod new_keys;
mod version_exchange;

pub use self::{
    client_server::ClientServer, cookie::Cookie, name_list::NameList, new_keys::NewKeys,
    version_exchange::VersionExchange,
};

/// Error emitted by the ssh protocol
#[derive(Debug)]
pub enum Error {
    /// Encoding error
    Encoding(EncodingError),
    /// Invalid command code found
    InvalidCommandCode { expected: u8, found: u8 },
    /// Key error
    Key(KeyError),
    /// Io error
    #[cfg(feature = "std")]
    Io(std::io::Error),
    /// Elliptic curve error
    #[cfg(feature = "ecdh")]
    EllipticCurve(elliptic_curve::Error),
}

impl From<EncodingError> for Error {
    fn from(e: EncodingError) -> Self {
        Self::Encoding(e)
    }
}

impl From<KeyError> for Error {
    fn from(e: KeyError) -> Self {
        Self::Key(e)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(feature = "ecdh")]
impl From<elliptic_curve::Error> for Error {
    fn from(e: elliptic_curve::Error) -> Self {
        Self::EllipticCurve(e)
    }
}

#[cfg(feature = "std")]
mod error_std {
    use super::Error;
    use std::{error, fmt, format};

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Encoding(e) => e.fmt(f),
                Self::InvalidCommandCode { expected, found } => {
                    write!(
                        f,
                        "invalid command code (found={found}, expected={expected})"
                    )
                }
                Self::Key(e) => e.fmt(f),
                Self::Io(e) => e.fmt(f),
                #[cfg(feature = "ecdh")]
                Self::EllipticCurve(e) => e.fmt(f),
            }
        }
    }

    impl error::Error for Error {}
}

#[inline]
fn read_command_code(command_code_expected: u8, reader: &mut impl Reader) -> Result<(), Error> {
    let mut command_code = [0u8; 1];
    reader.read(&mut command_code[..])?;

    if command_code[0] != command_code_expected {
        Err(Error::InvalidCommandCode {
            expected: command_code_expected,
            found: command_code[0],
        })
    } else {
        Ok(())
    }
}
