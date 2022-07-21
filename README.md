# GitHub webhook message validator

This package currently contains a single utility function, which may be used to validate the package
of a GitHub webhook request against a shared secret.

Note that if you get the signature from the `X-Hub-Signature` header, you'll need to convert it to
bytes via hex. One way is to use the
[hex crate decode_to_slice function](https://docs.rs/hex/0.4.3/hex/fn.decode_to_slice.html).

## Example

```rust
use github_webhook_message_validator::validate;

let signature = &vec![
    115, 109, 127, 147, 66, 242, 167, 210, 57, 175, 165, 81, 58, 75, 178, 40, 62, 14, 21, 136
];
let secret = b"some-secret";
let message = b"blah-blah-blah";

assert_eq!(validate(secret, signature, message), true);
