//! Protocol buffer codec for ABCI messages.
//!
//! Implements the Tendermint wire protocol using varint length-prefixing
//! for protobuf messages.

use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use std::io;
use tendermint_proto::v0_38::abci::{Request, Response};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum message size (10 MB).
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// ABCI message codec using varint length-prefixing.
///
/// Wire format:
/// - Varint encoded message length
/// - Protobuf encoded message
pub struct ABCICodec;

impl ABCICodec {
    /// Create a new ABCI codec.
    pub fn new() -> Self {
        ABCICodec
    }

    /// Encode varint length prefix.
    fn encode_varint(buf: &mut BytesMut, value: usize) {
        let mut n = value;
        loop {
            let mut byte = (n & 0x7F) as u8;
            n >>= 7;
            if n != 0 {
                byte |= 0x80;
            }
            buf.put_u8(byte);
            if n == 0 {
                break;
            }
        }
    }

    /// Decode varint length prefix.
    fn decode_varint(buf: &mut BytesMut) -> Option<usize> {
        let mut value = 0usize;
        let mut shift = 0;

        for i in 0..buf.len() {
            let byte = buf[i];
            value |= ((byte & 0x7F) as usize) << shift;

            if byte & 0x80 == 0 {
                buf.advance(i + 1);
                return Some(value);
            }

            shift += 7;
            if shift >= 64 {
                return None; // Overflow
            }
        }

        None // Need more data
    }
}

impl Default for ABCICodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder<Request> for ABCICodec {
    type Error = io::Error;

    fn encode(&mut self, item: Request, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Encode message to buffer
        let mut msg_buf = BytesMut::new();
        item.encode(&mut msg_buf).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Protobuf encode error: {}", e))
        })?;

        let msg_len = msg_buf.len();
        if msg_len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Message too large: {} bytes", msg_len),
            ));
        }

        // Reserve space for varint + message
        dst.reserve(10 + msg_len); // Max varint is 10 bytes

        // Encode length prefix
        Self::encode_varint(dst, msg_len);

        // Append message
        dst.extend_from_slice(&msg_buf);

        Ok(())
    }
}

impl Decoder for ABCICodec {
    type Item = Response;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        // Try to decode length prefix
        let msg_len = match Self::decode_varint(src) {
            Some(len) => len,
            None => return Ok(None), // Need more data
        };

        if msg_len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Message too large: {} bytes", msg_len),
            ));
        }

        // Check if we have the full message
        if src.len() < msg_len {
            // Reserve space for the rest of the message
            src.reserve(msg_len - src.len());
            return Ok(None);
        }

        // Decode message
        let msg_bytes = src.split_to(msg_len);
        let response = Response::decode(msg_bytes).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Protobuf decode error: {}", e))
        })?;

        Ok(Some(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendermint_proto::v0_38::abci::{request, response, RequestEcho, ResponseEcho};

    #[test]
    fn test_varint_encoding() {
        let mut buf = BytesMut::new();

        ABCICodec::encode_varint(&mut buf, 0);
        assert_eq!(buf[0], 0);
        buf.clear();

        ABCICodec::encode_varint(&mut buf, 127);
        assert_eq!(buf[0], 127);
        buf.clear();

        ABCICodec::encode_varint(&mut buf, 128);
        assert_eq!(&buf[..], &[0x80, 0x01]);
        buf.clear();

        ABCICodec::encode_varint(&mut buf, 300);
        assert_eq!(&buf[..], &[0xAC, 0x02]);
    }

    #[test]
    fn test_varint_decoding() {
        let mut buf = BytesMut::from(&[0][..]);
        assert_eq!(ABCICodec::decode_varint(&mut buf), Some(0));

        let mut buf = BytesMut::from(&[127][..]);
        assert_eq!(ABCICodec::decode_varint(&mut buf), Some(127));

        let mut buf = BytesMut::from(&[0x80, 0x01][..]);
        assert_eq!(ABCICodec::decode_varint(&mut buf), Some(128));

        let mut buf = BytesMut::from(&[0xAC, 0x02][..]);
        assert_eq!(ABCICodec::decode_varint(&mut buf), Some(300));

        // Incomplete varint
        let mut buf = BytesMut::from(&[0x80][..]);
        assert_eq!(ABCICodec::decode_varint(&mut buf), None);
    }

    #[test]
    fn test_encode_decode_message() {
        let mut codec = ABCICodec::new();
        let mut buf = BytesMut::new();

        // Create a test request
        let request = Request {
            value: Some(request::Value::Echo(RequestEcho {
                message: "hello".to_string(),
            })),
        };

        // Encode
        codec.encode(request.clone(), &mut buf).expect("encode failed");

        // Create response (simulating what app would send)
        let response = Response {
            value: Some(response::Value::Echo(ResponseEcho {
                message: "hello".to_string(),
            })),
        };

        // Encode response for testing decoder
        let mut response_buf = BytesMut::new();
        let mut msg_buf = BytesMut::new();
        response.encode(&mut msg_buf).expect("encode failed");
        ABCICodec::encode_varint(&mut response_buf, msg_buf.len());
        response_buf.extend_from_slice(&msg_buf);

        // Decode
        let decoded = codec.decode(&mut response_buf).expect("decode failed");
        assert!(decoded.is_some());
        let decoded_response = decoded.expect("response is some");

        match decoded_response.value {
            Some(response::Value::Echo(echo)) => {
                assert_eq!(echo.message, "hello");
            }
            _ => panic!("wrong response type"),
        }
    }

    #[test]
    fn test_decode_partial_message() {
        let mut codec = ABCICodec::new();

        // Create a message but only provide partial data
        let response = Response {
            value: Some(response::Value::Echo(ResponseEcho {
                message: "test".to_string(),
            })),
        };

        let mut full_buf = BytesMut::new();
        let mut msg_buf = BytesMut::new();
        response.encode(&mut msg_buf).expect("encode failed");
        ABCICodec::encode_varint(&mut full_buf, msg_buf.len());
        full_buf.extend_from_slice(&msg_buf);

        // Only provide first half of data
        let mid = full_buf.len() / 2;
        let mut partial_buf = BytesMut::from(&full_buf[..mid]);

        // Should return None (need more data)
        let result = codec.decode(&mut partial_buf).expect("decode should not error");
        assert!(result.is_none());
    }
}
