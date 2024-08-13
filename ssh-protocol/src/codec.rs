#![cfg(feature = "async")]
//! SSH framing codec.

use alloc::vec::Vec;
use core::{marker::PhantomData, mem::size_of};

use byteorder::{BigEndian, ReadBytesExt};
use encoding::{Decode, Encode};
use rand::rngs::StdRng;
use rand_core::{CryptoRngCore, SeedableRng};
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::Error;

/// Length of the packet length field
const PACKET_LEN: usize = size_of::<u32>();
/// Length of the padding length field
const PADDING_LEN: usize = size_of::<u8>();

const MAX_PADDING: usize = 12;

/// SSH framing codec.
///
/// This codec first reads an `u32` which indicates the length of the incoming
/// message. Then decodes the message using specified `Input` type.
///
/// The reverse transformation which appends the length of the encoded data
/// is also implemented for the given `Output` type.
#[derive(Debug)]
pub struct Codec<Input, Output, Rng = StdRng>
where
    Input: Decode,
    Output: Encode,
    Error: From<Input::Error>,
{
    rng: Rng,
    _input: PhantomData<Input>,
    _output: PhantomData<Output>,
}

impl<Input, Output> Default for Codec<Input, Output>
where
    Input: Decode,
    Output: Encode,
    Error: From<Input::Error>,
{
    fn default() -> Self {
        let rng = StdRng::from_entropy();
        Self {
            rng,
            _input: PhantomData,
            _output: PhantomData,
        }
    }
}

impl<Input, Output, Rng> Decoder for Codec<Input, Output, Rng>
where
    Input: Decode,
    Output: Encode,
    Error: From<Input::Error>,
{
    type Item = Input;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut bytes = &src[..];
        // Each packet is in the following format:
        //    uint32    packet_length

        if bytes.len() < PACKET_LEN {
            return Ok(None);
        }

        let packet_length = bytes.read_u32::<BigEndian>()? as usize;

        //    byte      padding_length
        if bytes.len() < PADDING_LEN {
            return Ok(None);
        }
        let padding_length = bytes.read_u8()? as usize;

        //    byte[n1]  payload; n1 = packet_length - padding_length - 1
        let Some((mut payload, bytes)) = bytes.split_at_checked(packet_length - padding_length - 1)
        else {
            return Ok(None);
        };

        //    byte[n2]  random padding; n2 = padding_length
        let Some((_padding, _bytes)) = bytes.split_at_checked(padding_length) else {
            return Ok(None);
        };

        //    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
        // TODO: inject mac, maybe
        //
        //    packet_length
        //       The length of the packet in bytes, not including 'mac' or the
        //       'packet_length' field itself.

        //    padding_length
        //       Length of 'random padding' (bytes).

        //    payload
        //       The useful contents of the packet.  If compression has been
        //       negotiated, this field is compressed.  Initially, compression
        //       MUST be "none".

        //    random padding
        //       Arbitrary-length padding, such that the total length of
        //       (packet_length || padding_length || payload || random padding)
        //       is a multiple of the cipher block size or 8, whichever is

        let message = Self::Item::decode(&mut payload)?;
        src.advance(PACKET_LEN + packet_length);
        Ok(Some(message))
    }
}

impl<Input, Output, Rng> Encoder<Output> for Codec<Input, Output, Rng>
where
    Rng: CryptoRngCore,
    Input: Decode,
    Output: Encode,
    Error: From<Input::Error>,
{
    type Error = Error;

    fn encode(&mut self, item: Output, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut bytes = Vec::new();

        let payload_len = item.encoded_len()? as u32;

        // Note that the length of the concatenation of 'packet_length',
        // 'padding_length', 'payload', and 'random padding' MUST be a multiple
        // of the cipher block size or 8, whichever is larger.  This constraint
        // MUST be enforced, even when using stream ciphers.  Note that the
        // 'packet_length' field is also encrypted, and processing it requires
        // special care when sending or receiving packets.  Also note that the
        // insertion of variable amounts of 'random padding' may help thwart
        // traffic analysis.
        let total_length = PACKET_LEN + PADDING_LEN + payload_len as usize;
        let mut padding_len: u8 = 8 - (total_length % 8) as u8;

        // There MUST be at least four bytes of padding.
        if padding_len < 4 {
            padding_len += 8;
        }

        let len = PADDING_LEN as u32 + payload_len + padding_len as u32;

        len.encode(&mut bytes).map_err(Error::Encoding)?;
        padding_len.encode(&mut bytes).map_err(Error::Encoding)?;

        item.encode(&mut bytes).map_err(Error::Encoding)?;

        let mut padding = [0u8; MAX_PADDING];
        self.rng.fill_bytes(&mut padding);
        bytes.extend_from_slice(&padding[..padding_len.into()]);

        dst.put(&*bytes);

        Ok(())
    }
}
