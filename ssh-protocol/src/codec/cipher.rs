use alloc::vec::Vec;
use core::marker::PhantomData;

use byteorder::{BigEndian, ReadBytesExt};
use cipher::{Cipher, Decryptor, Encryptor};
use digest::{
    array::Array,
    consts::U0,
    crypto_common::{KeyInit, KeySizeUser},
    typenum::Unsigned,
    Digest, FixedOutput, Output, OutputSizeUser, Update,
};
use encoding::{Decode, Encode, Error as EncodingError, Reader, Writer};
use hmac::{EagerHash, Hmac};
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use super::{Codec, PACKET_LEN};
use crate::{constants, key_exchange::SessionKeys, ClientServer, Error};

use pretty_hex::PrettyHex;

struct MacState<D>
where
    D: Digest,
{
    integrity_key: Output<D>,
    packet_id: u32,
}

/// State machine for reading from the
#[derive(Debug, PartialEq)]
enum ReadState {
    /// Initial state
    /// We have finished reading packet all the way up to that point, and are waiting for another
    /// packet
    Initial,

    /// Need more data from our peer
    /// We've read the start of the packet, decrypted it and we expect `packet_length` of data.
    NeedsMore {
        /// Length of the packet we are currently reading
        packet_length: usize,
    },
}

pub struct CipherCodec<D, M>
where
    D: Digest,
{
    mac: ClientServer<MacState<D>>,
    read_state: ReadState,
    read_cipher: Decryptor,
    write_cipher: Encryptor,
    _mac: PhantomData<M>,
}

impl<D, M> CipherCodec<D, M>
where
    D: Digest,
{
    pub fn new(session_keys: SessionKeys<D>, packet_id: ClientServer<u32>) -> Self {
        let mac = ClientServer {
            client_to_server: MacState {
                integrity_key: session_keys.integrity_key.client_to_server,
                packet_id: packet_id.client_to_server,
            },
            server_to_client: MacState {
                integrity_key: session_keys.integrity_key.server_to_client,
                packet_id: packet_id.server_to_client,
            },
        };

        let read_cipher = Decryptor::new(
            Cipher::Aes128Ctr,
            &session_keys.encryption_key.client_to_server[..16],
            &session_keys.initial_iv.client_to_server[..16],
        )
        .unwrap();
        let write_cipher = Encryptor::new(
            Cipher::Aes128Ctr,
            &session_keys.encryption_key.server_to_client[..16],
            &session_keys.initial_iv.server_to_client[..16],
        )
        .unwrap();
        let read_state = ReadState::Initial;

        Self {
            mac,
            read_state,
            read_cipher,
            write_cipher,
            _mac: PhantomData,
        }
    }
}

impl<D, M> Decoder for CipherCodec<D, M>
where
    D: Digest + EagerHash,
    M: Mac,
{
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // src is the encrypted payload, it may or may not be complete, but the
        // structure should look like this:
        //  [ length u32 BE ] [ padding length u8 ] [ message payload ... ]  \
        //  [ message payload ...]                                           | == This top half is encrypted
        //  [ message payload ...] [ padding ]                               /
        //  [ mac (length depends on the mac ALG) ]                          ===  MAC is never encrypted
        //
        // The idea here will be to decode the first 16 bytes (the length + padding is 5 bytes), the
        // whole packet needs to be aligned on 8 bytes, and the padding needs to be at least 4.

        if src.len() < 16 + M::OutputSize::USIZE {
            // We don't have a full packet, come back later
            return Ok(None);
        }

        let packet_length = match self.read_state {
            ReadState::Initial => {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&src[..16]);

                self.read_cipher.peek_decrypt(&mut buf[..]).unwrap();

                let mut bytes = &buf[..];

                let packet_length = bytes.read_u32::<BigEndian>()? as usize;

                // Packet length includes the padding length + payload + padding
                // but does not includes its own u32 encoding.
                if src.len() < PACKET_LEN + packet_length + M::OutputSize::USIZE {
                    self.read_state = ReadState::NeedsMore { packet_length };
                    // We don't have the full buffer yet
                    return Ok(None);
                }

                packet_length
            }
            ReadState::NeedsMore { packet_length } => {
                if src.len() < PACKET_LEN + packet_length + M::OutputSize::USIZE {
                    // We don't have the full buffer yet
                    return Ok(None);
                }
                self.read_state = ReadState::Initial;
                packet_length
            }
        };

        let payload_without_mac = PACKET_LEN + packet_length;
        self.read_cipher
            .decrypt(&mut src.as_mut()[..payload_without_mac])
            .unwrap();

        {
            let (to_hash, hash) = (&src[..]).split_at(payload_without_mac);

            let mut mac = M::new_from_slice(&self.mac.client_to_server.integrity_key).unwrap();
            mac.update(&self.mac.client_to_server.packet_id.to_be_bytes());
            self.mac.client_to_server.packet_id =
                self.mac.client_to_server.packet_id.wrapping_add(1);
            mac.update(to_hash);
            let result = mac.finalize_fixed();
            assert_eq!(result.as_slice(), hash);
        }

        let mut inner = Codec::<Message, Message>::default();
        let msg = inner.decode(src)?;
        src.advance(M::OutputSize::USIZE);

        Ok(msg)
    }
}

impl<D, M> Encoder<Message> for CipherCodec<D, M>
where
    D: Digest,
    M: Mac,
{
    type Error = Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut inner = Codec::<Message, Message>::default();
        inner.encode(item, dst)?;

        let mac = {
            let mut mac = M::new_from_slice(&self.mac.server_to_client.integrity_key).unwrap();
            mac.update(&self.mac.server_to_client.packet_id.to_be_bytes());
            self.mac.server_to_client.packet_id.wrapping_add(1);
            mac.update(&dst);
            mac.finalize_fixed()
        };

        {
            self.write_cipher.encrypt(dst.as_mut()).unwrap();
        }
        dst.put_slice(&mac);

        Ok(())
    }
}

#[derive(Debug)]
pub enum Message {
    Ignore(Vec<u8>),
    ServiceRequest { name: Vec<u8> },
    ServiceAccept { name: Vec<u8> },
}

impl Decode for Message {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let mut command_code = [0u8; 1];
        reader.read(&mut command_code[..])?;

        match command_code[0] {
            constants::SSH_MSG_IGNORE => {
                let msg = Vec::<u8>::decode(reader)?;
                Ok(Message::Ignore(msg))
            }
            constants::SSH_MSG_SERVICE_REQUEST => {
                let name = Vec::<u8>::decode(reader)?;
                Ok(Message::ServiceRequest { name })
            }
            other => unimplemented!(),
        }
    }
}

impl Encode for Message {
    #[inline]
    fn encoded_len(&self) -> Result<usize, EncodingError> {
        match self {
            Self::Ignore(msg) => Ok(1 + msg.encoded_len()?),
            Self::ServiceRequest { name } => Ok(1 + name.encoded_len()?),
            Self::ServiceAccept { name } => Ok(1 + name.encoded_len()?),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), EncodingError> {
        match self {
            Self::Ignore(msg) => {
                constants::SSH_MSG_IGNORE.encode(writer)?;
                msg.encode(writer)?;
            }
            Self::ServiceRequest { name } => {
                constants::SSH_MSG_SERVICE_REQUEST.encode(writer)?;
                name.encode(writer)?;
            }
            Self::ServiceAccept { name } => {
                constants::SSH_MSG_SERVICE_ACCEPT.encode(writer)?;
                name.encode(writer)?;
            }
        }
        Ok(())
    }
}

pub trait Mac: OutputSizeUser + KeyInit + FixedOutput {
    const IDENT: Option<&'static str>;
}

impl Mac for Hmac<sha2::Sha256> {
    const IDENT: Option<&'static str> = Some("hmac-sha2-256");
}

/// NullMac is intended for use along with an AEAD, where a mac is not necessary.
pub struct NullMac;

impl Mac for NullMac {
    const IDENT: Option<&'static str> = None;
}
impl KeySizeUser for NullMac {
    type KeySize = U0;
}
impl KeyInit for NullMac {
    fn new(_: &Array<u8, <Self as KeySizeUser>::KeySize>) -> Self {
        Self
    }
}
impl OutputSizeUser for NullMac {
    type OutputSize = U0;
}
impl Update for NullMac {
    fn update(&mut self, _: &[u8]) {}
}
impl FixedOutput for NullMac {
    fn finalize_into(self, _: &mut Array<u8, <Self as OutputSizeUser>::OutputSize>) {}
}
