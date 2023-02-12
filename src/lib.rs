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
    nonce: String,
}


impl SignedJsonMessage {
    pub fn new(key: &str, nonce: &str) -> SignedJsonMessage {
        SignedJsonMessage {
            key: key.to_string(),
            // XXX: remove nonce
            nonce: nonce.to_string(),
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
    pub fn nonce(&self) -> &String {
        return &self.nonce;
    }
    pub fn from_string(s: &str, key: &str, expected_nonce: &str) -> Result<SignedJsonMessage, String> {
        let sp: Vec<&str> = s.rsplitn(2, ".").collect();
        if sp.len() != 2 {
            return Err("invalid input data {s}".to_string());
        }
        let encoded_header_payload = sp[1];
        let encoded_signature = sp[0];
        let recv_sig = general_purpose::STANDARD.decode(encoded_signature).unwrap();
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("invalid size");
        mac.update(encoded_header_payload.as_bytes());
        match mac.verify_slice(&recv_sig) {
            Ok(s) => s,
            Err(error) => return Err(error.to_string()),
        }
        // XXX: compare protocol version and error on mismatch
        let sp: Vec<&str> = encoded_header_payload.splitn(2, ".").collect();
        if sp.len() != 2 {
            return Err("invalid input header/payload {s}".to_string());
        }
        let encoded_header = sp[0];
        let encoded_payload = sp[1];
        let header_bytes = general_purpose::STANDARD.decode(encoded_header).unwrap();
        let payload_bytes = general_purpose::STANDARD.decode(encoded_payload).unwrap();
        let header: HashMap<String, String> = serde_json::from_slice(header_bytes.as_slice()).expect("cannot read header json");
        let payload: HashMap<String, String> = serde_json::from_slice(payload_bytes.as_slice()).expect("cannot read payload json");
        if expected_nonce != "" {
            let nonce_item = header.get(&"nonce".to_string()).ok_or("cannot find nonce in header");
            let nonce = nonce_item.unwrap();
            if nonce != expected_nonce {
                return Err("invalid nonce".to_string());
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
        assert_eq!(msg.nonce, "nonce");
        assert_eq!(msg.nonce(), "nonce");
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
    fn signed_json_message_from_string() -> Result<(), String> {
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
        assert_eq!(err, "MAC tag mismatch".to_string());
    }
}
