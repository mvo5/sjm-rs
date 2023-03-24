use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
type HmacSha256 = Hmac<Sha256>;
use base64::Engine as _;

// tiny wrappers to avoid the overly verbose base64 naming
fn b64enc<T: AsRef<[u8]>>(input: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}
fn b64dec<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
}

#[derive(Debug, Clone)]
pub enum Error {
    InvalidInputData,
    InvalidHmacKey,
    InvalidHmacSignature,
    InvalidJsonData,
    MissingNonce,
    NonceMismatch,
    InvalidProtocolVersion,
}
impl std::error::Error for Error {}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidInputData => write!(f, "invalid input data"),
            Error::InvalidHmacKey => write!(f, "invalid hmac key"),
            Error::InvalidHmacSignature => write!(f, "invalid hmac signature"),
            Error::InvalidJsonData => write!(f, "invalid json data"),
            Error::MissingNonce => write!(f, "missing nonce "),
            Error::NonceMismatch => write!(f, "nonce mismatch"),
            Error::InvalidProtocolVersion => write!(f, "invalid protocol version"),
        }
    }
}

#[derive(Debug)]
pub struct SignedJsonMessage {
    // XXX: is this the best way make payload public? setter/getter did not work really well
    /// The payload is application specific data that is part of the SJM
    pub payload: HashMap<String, String>,

    header: HashMap<String, String>,
    // TODO: key must become something like "Vec<u8>" instead
    key: String,
}

impl SignedJsonMessage {
    pub fn new(key: &str, nonce: &str) -> SignedJsonMessage {
        SignedJsonMessage {
            key: key.to_string(),
            // XXX: is there a better way to init defaults?
            header: HashMap::from([
                ("ver".to_string(), "1".to_string()),
                ("alg".to_string(), "HS256".to_string()),
                ("nonce".to_string(), nonce.to_string()),
            ]),
            payload: HashMap::new(),
        }
    }

    pub fn nonce(&self) -> Option<&String> {
        self.header.get("nonce")
    }

    pub fn from_string(
        s: &str,
        key: &str,
        expected_nonce: &str,
    ) -> Result<SignedJsonMessage, Error> {
        let (encoded_header_payload, encoded_signature) =
            s.rsplit_once('.').ok_or(Error::InvalidInputData)?;
        let recv_sig = b64dec(encoded_signature).map_err(|_| Error::InvalidInputData)?;
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| Error::InvalidHmacKey)?;
        mac.update(encoded_header_payload.as_bytes());
        mac.verify_slice(&recv_sig)
            .map_err(|_| Error::InvalidHmacSignature)?;
        let (encoded_header, encoded_payload) = encoded_header_payload
            .split_once('.')
            .ok_or(Error::InvalidInputData)?;
        let header_bytes = b64dec(encoded_header).map_err(|_| Error::InvalidInputData)?;
        let payload_bytes = b64dec(encoded_payload).map_err(|_| Error::InvalidInputData)?;
        let header: HashMap<String, String> =
            serde_json::from_slice(header_bytes.as_slice()).map_err(|_| Error::InvalidJsonData)?;
        let nonce = header.get(&"nonce".to_string()).map_or("", String::as_ref);
        if !expected_nonce.is_empty() && expected_nonce != nonce {
            return Err(Error::NonceMismatch);
        }
        let ver = header.get(&"ver".to_string()).map_or("", String::as_ref);
        if ver != "1" {
            return Err(Error::InvalidProtocolVersion);
        }
        // only decode the payload after everything is validated
        let payload: HashMap<String, String> =
            serde_json::from_slice(payload_bytes.as_slice()).map_err(|_| Error::InvalidJsonData)?;
        let mut msg = SignedJsonMessage::new(key, nonce);
        msg.payload = payload;
        Ok(msg)
    }

    pub fn to_string(&self) -> Result<String, Error> {
        let json_header =
            serde_json::to_string(&self.header).map_err(|_| Error::InvalidInputData)?;
        let encoded_json_header = b64enc(json_header);
        let json_payload =
            serde_json::to_string(&self.payload).map_err(|_| Error::InvalidInputData)?;
        let encoded_json_payload = b64enc(json_payload);
        let hp = format!("{encoded_json_header}.{encoded_json_payload}");
        let mut mac =
            HmacSha256::new_from_slice(self.key.as_bytes()).map_err(|_| Error::InvalidHmacKey)?;
        mac.update(hp.as_bytes());
        let sig = mac.finalize();
        let encoded_sig = b64enc(sig.into_bytes());

        Ok(format!("{hp}.{encoded_sig}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_signed_json_message() {
        let msg = SignedJsonMessage::new("key", "nonce");
        assert_eq!(msg.key, "key");
        assert_eq!(msg.nonce(), Some(&"nonce".to_string()));
    }

    #[test]
    fn signed_json_message_payload() {
        let mut msg = SignedJsonMessage::new("key", "nonce");
        msg.payload = HashMap::from([("foo".to_string(), "bar".to_string())]);
        assert_eq!(msg.payload.len(), 1);
        assert_eq!(
            msg.payload.get(&"foo".to_string()),
            Some(&"bar".to_string())
        );
    }

    #[test]
    fn signed_json_message_new() -> Result<(), Error> {
        // create a signed message and encode as string
        let mut msg = SignedJsonMessage::new("key", "nonce");
        msg.payload = HashMap::from([("foo".to_string(), "bar".to_string())]);
        let s = msg.to_string()?;
        // XXX: test more
        assert_eq!(s.matches(".").count(), 2);

        Ok(())
    }

    #[test]
    fn signed_json_message_integration() -> Result<(), Error> {
        // create a signed message and encode as string
        let mut msg = SignedJsonMessage::new("key", "nonce");
        msg.payload = HashMap::from([("foo".to_string(), "bar".to_string())]);
        let s = msg.to_string()?;

        // read back with invalid key
        let res = SignedJsonMessage::from_string(&s, "invalid-key", "nonce");
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(matches!(err, Error::InvalidHmacSignature));

        // read back with invalid nonce
        let res = SignedJsonMessage::from_string(&s, "key", "invalid-nonce");
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(matches!(err, Error::NonceMismatch));

        // read back, no nonce expected
        let msg2 = SignedJsonMessage::from_string(&s, "key", "")?;
        assert_eq!(msg2.nonce().expect("nonce missing"), "nonce");

        Ok(())
    }

    #[test]
    fn signed_json_message_from_string() -> Result<(), Error> {
        let msg = SignedJsonMessage::from_string("eyJhbGciOiJIUzI1NiIsIm5vbmNlIjoibm9uY2UiLCJ2ZXIiOiIxIn0=.eyJmb28iOiJiYXIifQ==.5sO1KIJIGn/ZAAwvWui9/gIHrfntLYFVnz57aMBOCCY=", "key", "nonce")?;
        assert_eq!(msg.payload.len(), 1);
        assert_eq!(
            msg.payload.get(&"foo".to_string()),
            Some(&"bar".to_string())
        );
        Ok(())
    }

    #[test]
    fn signed_json_message_invalid_hmac_signature() {
        let result = SignedJsonMessage::from_string("eyJhbGciOiJIUzI1NiIsIm5vbmNlIjoibm9uY2UiLCJ2ZXIiOiIxIn0=.eyJmb28iOiJiYXIifQ==.5sO1KIJIGn/ZAAwvWui9/xxxrfntLYFVnz57aMBOCCY=", "key", "nonce");
        assert_eq!(result.is_err(), true);
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidHmacSignature));
    }

    #[test]
    fn signed_json_message_invalid_string() {
        // not enough "."
        let result = SignedJsonMessage::from_string("invalid", "key", "nonce");
        assert_eq!(result.is_err(), true);
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidInputData));

        // invalid b64
        let result = SignedJsonMessage::from_string("x.y.z", "key", "nonce");
        assert_eq!(result.is_err(), true);
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidInputData));

        // no valid json header (but valid sig)
        let header_payload = format!("{}.{}", b64enc("nojson"), b64enc("{}"));
        let mut mac = HmacSha256::new_from_slice("key".as_bytes()).expect("invalid length");
        mac.update(header_payload.as_bytes());
        let sig = b64enc(mac.finalize().into_bytes());
        let result =
            SignedJsonMessage::from_string(&format!("{}.{}", header_payload, sig), "key", "nonce");
        assert_eq!(result.is_err(), true);
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "invalid json data");
        assert!(matches!(err, Error::InvalidJsonData));
    }
}
