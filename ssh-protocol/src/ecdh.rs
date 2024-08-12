#![cfg(feature = "ecdh")]
//! ECDH key exchange

use alloc::vec::Vec;
use std::io;

use digest::{Digest, Update};
use ecdsa::{EcdsaCurve, Signature, SignatureSize};
use elliptic_curve::{
    array::ArraySize,
    point::PointCompression,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey,
};
use encoding::{
    self, CheckedSum, Decode, DigestWriter, Encode, Error as EncodingError, Reader, Writer,
};
use futures::{sink::SinkExt, stream::StreamExt};
use key::{
    public::{EcdsaPublicKey, KeyData},
    Error as KeyError, Mpint,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use super::{
    codec::Codec, constants, key_exchange::KeyExchangeInit, read_command_code, Error,
    VersionExchange,
};

/// Client-initiated ECDH request
///
/// This contains the ephemeral public key of the client.
#[derive(Clone, Debug)]
pub struct EcdhInit<C>
where
    C: CurveArithmetic,
{
    /// Ephemeral EC public key
    pub public_key: PublicKey<C>,
}

impl<C> Encode for EcdhInit<C>
where
    C: CurveArithmetic + PointCompression,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn encoded_len(&self) -> Result<usize, EncodingError> {
        let out = self.public_key.to_sec1_bytes();

        [
            1, // command code
            out.len(),
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), EncodingError> {
        constants::SSH_MSG_KEX_ECDH_INIT.encode(writer)?;
        let out = self.public_key.to_sec1_bytes();

        out.encode(writer)
    }
}

impl<C> Decode for EcdhInit<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        read_command_code(constants::SSH_MSG_KEX_ECDH_INIT, reader)?;

        let public_bytes = Vec::<u8>::decode(reader)?;
        let public_key = PublicKey::from_sec1_bytes(&public_bytes)?;
        Ok(Self { public_key })
    }
}

#[cfg(feature = "async")]
impl<C> EcdhInit<C>
where
    C: CurveArithmetic + PointCompression,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    /// Receive an ecdh from a client.
    pub async fn receive<S>(stream: &mut S) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let codec = Codec::<Self, Self>::default();
        let mut stream = Framed::new(stream, codec);

        let Some(msg) = stream.next().await else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer disconnected").into());
        };

        Ok(msg?)
    }
}

/// The exchange hash H is computed as the hash of the concatenation of
/// the following:
/// ```
///    string   V_C, client's identification string (CR and LF excluded)
///    string   V_S, server's identification string (CR and LF excluded)
///    string   I_C, payload of the client's SSH_MSG_KEXINIT
///    string   I_S, payload of the server's SSH_MSG_KEXINIT
///    string   K_S, server's public host key
///    string   Q_C, client's ephemeral public key octet string
///    string   Q_S, server's ephemeral public key octet string
///    mpint    K,   shared secret
/// ```
pub struct ExchangeHash;

impl ExchangeHash {
    /// Compute the hash of the Exchange hash for this session
    pub fn compute<C, D>(
        client_version: &VersionExchange,
        server_version: &VersionExchange,
        client_kex: &KeyExchangeInit,
        server_kex: &KeyExchangeInit,
        server_public: &EcdsaPublicKey,
        client_ephemeral: &PublicKey<C>,
        server_ephemeral: &PublicKey<C>,
        shared_key: &Mpint,
    ) -> Result<D, Error>
    where
        D: Digest + Update,
        C: CurveArithmetic + PointCompression + EcdsaCurve,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        let mut digest_msg = D::new();
        let mut writer = DigestWriter(&mut digest_msg);

        client_version.encode(&mut writer)?;
        server_version.encode(&mut writer)?;
        client_kex.encode_prefixed(&mut writer)?;
        server_kex.encode_prefixed(&mut writer)?;
        let server_public = KeyData::from(server_public.clone());
        server_public.encode_prefixed(&mut writer)?;
        client_ephemeral.to_sec1_bytes().encode(&mut writer)?;
        server_ephemeral.to_sec1_bytes().encode(&mut writer)?;
        shared_key.encode(&mut writer)?;

        Ok(digest_msg)
    }
}

/// ECDH reply
///
/// See: <https://datatracker.ietf.org/doc/html/rfc5656#page-7>
#[derive(Clone, Debug)]
pub struct EcdhReply<C>
where
    C: CurveArithmetic + EcdsaCurve,
    SignatureSize<C>: ArraySize,
{
    /// Public identity of a server
    pub server_public: EcdsaPublicKey,
    /// Public ephemeral key of the server
    pub server_ephemeral: PublicKey<C>,
    /// Signature of the public ephemeral key by the server's private
    pub signature: key::Signature,
}

impl<C> Encode for EcdhReply<C>
where
    C: CurveArithmetic + PointCompression + EcdsaCurve,
    SignatureSize<C>: ArraySize,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    key::Signature: for<'a> TryFrom<&'a Signature<C>, Error = key::Error>,
{
    fn encoded_len(&self) -> Result<usize, EncodingError> {
        let server_public = KeyData::from(self.server_public.clone());

        [
            1, // command code
            server_public.encoded_len_prefixed()?,
            4,
            self.server_ephemeral.to_sec1_bytes().len(),
            self.signature.encoded_len_prefixed()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), EncodingError> {
        constants::SSH_MSG_KEX_ECDH_REPLY.encode(writer)?;

        let server_public = KeyData::from(self.server_public.clone());
        server_public.encode_prefixed(writer)?;
        self.server_ephemeral.to_sec1_bytes().encode(writer)?;
        self.signature.encode_prefixed(writer)?;

        Ok(())
    }
}

impl<C> Decode for EcdhReply<C>
where
    C: CurveArithmetic + EcdsaCurve,
    SignatureSize<C>: ArraySize,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,

    Signature<C>: for<'a> TryFrom<&'a key::Signature, Error = key::Error>,
{
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        read_command_code(constants::SSH_MSG_KEX_ECDH_REPLY, reader)?;

        let server_public = reader.read_prefixed(|reader| KeyData::decode(reader))?;
        let server_public = server_public.ecdsa().cloned().ok_or(KeyError::PublicKey)?;

        let server_ephemeral_bytes = Vec::<u8>::decode(reader)?;
        let server_ephemeral = PublicKey::from_sec1_bytes(&server_ephemeral_bytes)?;

        let signature = reader.read_prefixed(|reader| key::Signature::decode(reader))?;

        Ok(Self {
            server_public,
            server_ephemeral,
            signature,
        })
    }
}

#[cfg(feature = "async")]
impl<C> EcdhReply<C>
where
    C: CurveArithmetic + EcdsaCurve + PointCompression,
    SignatureSize<C>: ArraySize,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,

    Signature<C>: for<'a> TryFrom<&'a key::Signature, Error = key::Error>,
    key::Signature: for<'a> TryFrom<&'a Signature<C>, Error = key::Error>,
{
    /// Send this ECDH reply to the client
    pub async fn send<S>(&self, stream: &mut S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let codec = Codec::<Self, Self>::default();
        let mut stream = Framed::new(stream, codec);

        stream.send(self.clone()).await.map_err(|_e| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client disconnected before saying hello, how rude",
            )
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_parse_ecdh_reply() {
        let payload: &[u8] = &hex!(
            "1f 0000 0068 0000
	  0013 6563 6473 612d 7368 6132 2d6e 6973
	  7470 3235 3600 0000 086e 6973 7470 3235
	  3600 0000 4104 733a eca1 8964 f437 d429
	  592c 4092 7bb5 14f8 2e13 3288 bafb 654a
	  4c40 b24d b55c 3857 4e0a 27d0 e184 1748
	  2d02 87c1 cede 8d79 b158 abcb 0f7f fc8b
	  35fd 8e96 8f02 0000 0041 0464 5e0f 5201
	  8eb7 d671 7331 68be b892 01d5 6c58 966d
	  4d66 571a a1f3 b6a3 c95b 9f37 e949 64cc
	  b490 0f51 7102 dbde cd24 5414 3590 f4ba
	  edc0 6dca a156 8bbe f98f d100 0000 6500
	  0000 1365 6364 7361 2d73 6861 322d 6e69
	  7374 7032 3536 0000 004a 0000 0021 00dc
	  956f 4fd1 e79e 5892 f112 0fb2 4272 83a4
	  4cb8 c763 4272 c2f5 324a 84cd ebb5 2500
	  0000 2100 a026 f7af c4a8 13ef a961 1306
	  292f ab34 b1c4 6810 d70f ca78 5705 f0f9
	  92d5 1321"
        );
        let mut parsing: &[u8] = payload;

        let reply = EcdhReply::<p256::NistP256>::decode(&mut parsing).unwrap();
        let mut out = Vec::new();
        reply.encode(&mut out);

        assert_eq!(payload, out);
    }
}
