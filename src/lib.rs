pub struct SignedJsonMessage {
    key: String,
    nonce: String,
    // XXX: this needs to be a HashMap
    payload: String,
}

impl SignedJsonMessage {
    pub fn new(key: &str, nonce: &str) -> SignedJsonMessage {
        SignedJsonMessage{
            key: key.to_string(),
            nonce: nonce.to_string(),
            // XXX: is there a better way to init defaults?
            payload: "".to_string(),
        }
    }
    pub fn set_payload(&mut self, payload: &str) {
        self.payload = payload.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_signed_json_message() {
        let msg = SignedJsonMessage::new("key","nonce");
        assert_eq!(msg.key, "key");
        assert_eq!(msg.nonce, "nonce");
    }

    #[test]
    fn signed_json_message_set_payload() {
        let mut msg = SignedJsonMessage::new("key","nonce");
        msg.set_payload("my-payload");
        assert_eq!(msg.payload, "my-payload");
    }
}
