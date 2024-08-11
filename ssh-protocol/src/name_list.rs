#![cfg(feature = "alloc")]

use alloc::{string::String, vec::Vec};

use encoding::{self, CheckedSum, Decode, Encode, Error as EncodingError, Reader, Writer};

use super::Error;

/// [`NameList`] are comma-separated lists of algorithm names.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NameList(pub Vec<String>);

impl Decode for NameList {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let name_list = String::decode(reader)?;
        if name_list.is_empty() {
            Ok(Self(Vec::new()))
        } else {
            Ok(Self(name_list.split(',').map(String::from).collect()))
        }
    }
}

impl Encode for NameList {
    #[inline]
    fn encoded_len(&self) -> Result<usize, EncodingError> {
        let commas = if self.0.len() > 0 {
            self.0.len() - 1
        } else {
            0
        };

        let prefix = [4, commas].checked_sum()?;

        self.0.iter().try_fold(prefix, |acc, el| {
            usize::checked_add(acc, el.len()).ok_or(EncodingError::Length)
        })
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), EncodingError> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        if let Some((first, rest)) = self.0.split_first() {
            out.extend_from_slice(first.as_bytes());
            for item in rest {
                out.push(b',');
                out.extend_from_slice(item.as_bytes());
            }
        }

        out.len().encode(writer)?;
        writer.write(&out)
    }
}

impl From<Vec<String>> for NameList {
    fn from(inner: Vec<String>) -> Self {
        Self(inner)
    }
}
