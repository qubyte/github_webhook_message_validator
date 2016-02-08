//! The `github_webhook_message_validator` crate provides functions to validating GitHub webhook
//! notifications.

extern crate crypto;

use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha1::Sha1;


/// Check a signature and a message against a shared secret.
///
/// Note that if you get the signature from the `X-Hub-Signature` header, you'll need to convert it
/// to bytes via hex. Use the `rustc_serialize` `From_Hex` trait to do this.
///
/// # Examples
///
/// ```
/// use github_webhook_message_validator::validate;
///
/// let signature = &vec![
///     115, 109, 127, 147, 66, 242, 167, 210, 57, 175, 165, 81, 58, 75, 178, 40, 62, 14, 21, 136
/// ];
/// let secret = b"some-secret";
/// let message = b"blah-blah-blah";
///
/// assert_eq!(validate(secret, signature, message), true);
/// ```
pub fn validate(secret: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let mut hmac = Hmac::new(Sha1::new(), secret);
    hmac.input(&message[..]);
    hmac.result() == MacResult::new(&signature[..])
}

#[cfg(test)]
mod test {
    use validate;

    #[test]
    fn it_returns_true_when_signature_and_message_match() {
        let signature = &vec![
            0x73, 0x6d, 0x7f, 0x93, 0x42,
            0xf2, 0xa7, 0xd2, 0x39, 0xaf,
            0xa5, 0x51, 0x3a, 0x4b, 0xb2,
            0x28, 0x3e, 0x0e, 0x15, 0x88
        ];
        let secret = b"some-secret";
        let message = b"blah-blah-blah";

        assert_eq!(validate(secret, signature, message), true);
    }

    #[test]
    fn it_returns_false_when_signature_and_message_do_not_match() {
        let signature = &vec![
            0x31, 0x30, 0x2b, 0x00, 0xba,
            0xd4, 0xd6, 0xd1, 0x10, 0xa1,
            0x18, 0x82, 0x77, 0xc4, 0xd1,
            0x06, 0x0c, 0xb2, 0xc3, 0x73
        ];
        let secret = b"some-secret";
        let message = b"blah-blah-blah?";

        assert_eq!(validate(secret, signature, message), false);
    }
}
