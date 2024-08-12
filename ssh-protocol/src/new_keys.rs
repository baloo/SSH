use std::io;

use encoding::{self, Decode, Encode, Error as EncodingError, Reader, Writer};
use futures::{sink::SinkExt, stream::StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::{codec::Codec, constants, read_command_code, Error};

/// Key Exchange completion
///
/// Both parties just agreed on a set of keys and are ready to send
/// encrypted payloads to each other.
#[derive(Copy, Clone, Debug)]
pub struct NewKeys;

impl NewKeys {
    /// Tell our peer we're ready to send encrypted payloads,
    /// and wait their readiness.
    pub async fn exchange<S>(&self, stream: &mut S) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let codec = Codec::<Self, Self>::default();
        let mut stream = Framed::new(stream, codec);

        stream
            .send(self.clone())
            .await
            .map_err(|_e| io::Error::new(io::ErrorKind::UnexpectedEof, "peer disconnected"))?;

        let Some(msg) = stream.next().await else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer disconnected").into());
        };

        Ok(msg?)
    }
}

impl Encode for NewKeys {
    fn encoded_len(&self) -> Result<usize, EncodingError> {
        Ok(1)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), EncodingError> {
        constants::SSH_MSG_NEWKEYS.encode(writer)?;
        Ok(())
    }
}

impl Decode for NewKeys {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        read_command_code(constants::SSH_MSG_NEWKEYS, reader)?;

        Ok(Self)
    }
}
