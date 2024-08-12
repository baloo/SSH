use encoding::{self, CheckedSum, Decode, Encode, Error as EncodingError, Reader, Writer};

/// [`ClientServer`] holds a pair of algorithm list from client to server and server to client.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClientServer<T> {
    /// Client to server list of algorithms
    pub client_to_server: T,
    /// Server to client list of algorithms
    pub server_to_client: T,
}

impl<T> ClientServer<T> {
    /// Create a new pair of protocols from a list. This duplicates the list of algorithms in both
    /// ways.
    pub fn new(inner: T) -> Self
    where
        T: Clone,
    {
        Self {
            client_to_server: inner.clone(),
            server_to_client: inner,
        }
    }
}

impl<T> Decode for ClientServer<T>
where
    T: Decode,
{
    type Error = T::Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let client_to_server = T::decode(reader)?;
        let server_to_client = T::decode(reader)?;
        Ok(Self {
            client_to_server,
            server_to_client,
        })
    }
}

impl<T> Encode for ClientServer<T>
where
    T: Encode,
{
    #[inline]
    fn encoded_len(&self) -> Result<usize, EncodingError> {
        [
            self.client_to_server.encoded_len()?,
            self.server_to_client.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), EncodingError> {
        self.client_to_server.encode(writer)?;
        self.server_to_client.encode(writer)
    }
}
