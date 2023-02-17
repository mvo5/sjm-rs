use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
type HmacSha256 = Hmac<Sha256>;
use base64::{engine::general_purpose, Engine as _};

#[derive(Debug)]
pub struct SignedJsonMessage {
    header: HashMap<String, String>,
    payload: HashMap<String, String>,

    key: String,
}

#[derive(Debug, Clone)]
pub struct SignedJsonMessageError {
    msg: String,
}
impl std::error::Error for SignedJsonMessageError{}
impl SignedJsonMessageError {
    pub fn new(msg: &str) -> SignedJsonMessageError {
        return SignedJsonMessageError {
            msg: msg.to_string(),
        };
    }
}
impl fmt::Display for SignedJsonMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
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
    pub fn set_payload(&mut self, payload: HashMap<String, String>) {
        self.payload = payload;
    }
    pub fn payload(&self) -> &HashMap<String, String> {
        return &self.payload;
    }
    pub fn nonce(&self) -> Option<&String> {
        return self.header.get("nonce");
    }
    pub fn from_string(
        s: &str,
        key: &str,
        expected_nonce: &str,
    ) -> Result<SignedJsonMessage, SignedJsonMessageError> {
        let sp: Vec<&str> = s.rsplitn(2, ".").collect();
        if sp.len() != 2 {
            return Err(SignedJsonMessageError::new(&format!(
                "invalid input data {s}"
            )));
        }
        let encoded_header_payload = sp[1];
        let encoded_signature = sp[0];
        let recv_sig = general_purpose::STANDARD.decode(encoded_signature).unwrap();
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("invalid size");
        mac.update(encoded_header_payload.as_bytes());
        match mac.verify_slice(&recv_sig) {
            Ok(s) => s,
            Err(error) => return Err(SignedJsonMessageError::new(&error.to_string())),
        }
        // XXX: compare protocol version and error on mismatch
        let sp: Vec<&str> = encoded_header_payload.splitn(2, ".").collect();
        if sp.len() != 2 {
            return Err(SignedJsonMessageError::new(&format!(
                "invalid input header/payload {s}"
            )));
        }
        let header_bytes = general_purpose::STANDARD.decode(sp[0]).unwrap();
        let payload_bytes = general_purpose::STANDARD.decode(sp[1]).unwrap();
        let header: HashMap<String, String> = serde_json::from_slice(header_bytes.as_slice())
            .map_err(|_| SignedJsonMessageError::new("cannot read header json"))?;
        let payload: HashMap<String, String> = serde_json::from_slice(payload_bytes.as_slice())
            .map_err(|_| SignedJsonMessageError::new("cannot read payload json"))?;
        if expected_nonce != "" {
            let nonce = header
                .get(&"nonce".to_string())
                .ok_or(SignedJsonMessageError::new("cannot find nonce in header"))?;
            if nonce != expected_nonce {
                return Err(SignedJsonMessageError::new("invalid nonce"));
            }
        }

        let mut msg = SignedJsonMessage::new(key, expected_nonce);
        msg.set_payload(payload);
        Ok(msg)
    }
}

impl fmt::Display for SignedJsonMessage {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let json_header = match serde_json::to_string(&self.header) {
            Ok(str) => str,
            Err(error) => error.to_string(),
        };
        let encoded_json_header = general_purpose::STANDARD.encode(json_header);
        let json_payload = match serde_json::to_string(&self.payload) {
            Ok(str) => str,
            Err(error) => error.to_string(),
        };
        let encoded_json_payload = general_purpose::STANDARD.encode(json_payload);
        let hp = format!("{encoded_json_header}.{encoded_json_payload}");
        // XXX: can this expect be avoided?
        let mut mac = HmacSha256::new_from_slice(&self.key.as_bytes()).expect("invalid length");
        mac.update(hp.as_bytes());
        let sig = mac.finalize();
        let encoded_sig = general_purpose::STANDARD.encode(sig.into_bytes());
        fmt.write_str(&format!("{hp}.{encoded_sig}"))?;
        Ok(())
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
    fn signed_json_message_set_payload() {
        let mut msg = SignedJsonMessage::new("key", "nonce");
        msg.set_payload(HashMap::from([("foo".to_string(), "bar".to_string())]));
        assert_eq!(msg.payload().len(), 1);
        assert_eq!(
            msg.payload().get(&"foo".to_string()),
            Some(&"bar".to_string())
        );
    }

    #[test]
    fn signed_json_message_to_str() {
        let mut msg = SignedJsonMessage::new("key", "nonce");
        msg.set_payload(HashMap::from([("foo".to_string(), "bar".to_string())]));
        // TODO: test!
        println!("xxx {msg}");
    }

    #[test]
    fn signed_json_message_from_string() -> Result<(), SignedJsonMessageError> {
        let msg = SignedJsonMessage::from_string("eyJhbGciOiJIUzI1NiIsIm5vbmNlIjoibm9uY2UiLCJ2ZXIiOiIxIn0=.eyJmb28iOiJiYXIifQ==.5sO1KIJIGn/ZAAwvWui9/gIHrfntLYFVnz57aMBOCCY=", "key", "nonce")?;
        assert_eq!(msg.payload().len(), 1);
        assert_eq!(
            msg.payload().get(&"foo".to_string()),
            Some(&"bar".to_string())
        );
        Ok(())
    }

    #[test]
    fn signed_json_message_from_invalid_string() {
        let result = SignedJsonMessage::from_string("eyJhbGciOiJIUzI1NiIsIm5vbmNlIjoibm9uY2UiLCJ2ZXIiOiIxIn0=.eyJmb28iOiJiYXIifQ==.5sO1KIJIGn/ZAAwvWui9/xxxrfntLYFVnz57aMBOCCY=", "key", "nonce");
        assert_eq!(result.is_err(), true);
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "MAC tag mismatch");
    }
}
