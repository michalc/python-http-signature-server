# http-signature-server

HTTP server agnostic Python implementation of the server side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00), with [cryptography](https://github.com/pyca/cryptography) the only dependency other than the Python standard library.

A deliberate subset of the signature algorithm is implemented:

- requests must be signed using an Ed25519 private key [currently seen as a good algorithm];
- a SHA-512 digest of the body is required [to authenticate more of the request];
- the algorithm parameter is not checked [it should not be used to choose the algorithm].

> This is a work in progress. This README serves as a rough design spec.


## Usage

```python
from http_signature_server import verify_ed25519_sha512

def get_verifier(key_id):
    # If the key_id is found, return a callable that takes the signature and key_id and returns a bool
    # If the key_id isn't known, return None

error, (key_id, verified_headers) = verify_ed25519_sha512(get_verifier, method, url, headers, body_sha512)
```
