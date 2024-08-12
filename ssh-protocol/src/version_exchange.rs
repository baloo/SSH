use alloc::{
    format,
    string::{String, ToString},
};
use std::io;

use encoding::{self, Encode, Error as EncodingError, Writer};

use futures::{sink::SinkExt, stream::StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};

use crate::Error;

/// Protocol Version Exchange
///
/// When the connection has been established, both sides MUST send an
/// identification string.  This identification string MUST be
///
///   SSH-protoversion-softwareversion SP comments CR LF
///
/// Here protoversion is hardcoded to "2.0"
pub struct VersionExchange {
    /// Software version
    pub software_version: String,
    /// Comment on the version
    pub comment: Option<String>,
}

impl VersionExchange {
    pub(crate) fn payload(&self) -> String {
        let comment = self
            .comment
            .as_ref()
            .map(|c| format!(" {c}"))
            .unwrap_or_default();
        format!(
            "SSH-2.0-{swversion}{comment}",
            swversion = self.software_version
        )
    }

    /// Send our version and wait for the peer's version
    #[cfg(feature = "async")]
    pub async fn exchange<S>(&self, stream: &mut S) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // The maximum length of the string is 255 characters, including the
        // Carriage Return and Line Feed.
        // TODO(baloo): does max_length in tokio include the CRLF?
        // TODO(baloo): can we make LinesCodec read CRLF?
        let codec = LinesCodec::new_with_max_length(255);

        let mut stream = Framed::new(stream, codec);

        // NOTE: this blocks until flushed, get that in tokio::join
        let mut payload = self.payload();
        payload.push_str("\r");
        stream.send(payload).await.map_err(|e| match e {
            LinesCodecError::MaxLineLengthExceeded => {
                io::Error::new(io::ErrorKind::InvalidData, "outbound buffer is too long")
            }
            LinesCodecError::Io(e) => e,
        })?;

        // NOTE: the server may send a banner, but this not implemented here yet.

        let Some(header) = stream.next().await else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client disconnected before saying hello, how rude",
            )
            .into());
        };

        let header = header.map_err(|e| match e {
            LinesCodecError::MaxLineLengthExceeded => {
                io::Error::new(io::ErrorKind::InvalidData, "inbound buffer is too long")
            }
            LinesCodecError::Io(e) => e,
        })?;

        const PREFIX: &str = "SSH-2.0-";
        if !header.starts_with(PREFIX) {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "Only SSH 2.0 is supported").into(),
            );
        }

        // TODO: this one is weird? Codec strips off the trailing CR?
        //if !header.ends_with("\r") {
        //    return Err(io::Error::new(
        //        io::ErrorKind::InvalidInput,
        //        "CRLF expected at the end of the line",
        //    ));
        //}
        //let buffer = &header[PREFIX.len()..header.len() - 1];

        // TODO: finish that for real, this should split comment
        Ok(Self {
            software_version: header[PREFIX.len()..].to_string(),
            comment: None,
        })
    }
}

impl Encode for VersionExchange {
    fn encoded_len(&self) -> Result<usize, EncodingError> {
        let payload = self.payload();
        payload.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), EncodingError> {
        let payload = self.payload();
        payload.encode(writer)
    }
}
