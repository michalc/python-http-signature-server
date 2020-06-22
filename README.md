# http-signature-server [![CircleCI](https://circleci.com/gh/michalc/python-http-signature-server.svg?style=shield)](https://circleci.com/gh/michalc/python-http-signature-server) [![Test Coverage](https://api.codeclimate.com/v1/badges/13edfb23364413ec24c3/test_coverage)](https://codeclimate.com/github/michalc/python-http-signature-server/test_coverage)

HTTP server agnostic Python implementation of the server side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00), with no dependencies other than the Python standard library, although [cryptography](https://github.com/pyca/cryptography) would typically be used in client code to verify signatures using a public key.


## Usage

```python
from http_signature_server import verify

def lookup_verifier(key_id):
    # If the key_id is found, return a callable that takes the signature and
    # data to verify, returning True only if the signature verifies the data
    # If the key_id isn't found, return None

error, (key_id, verified_headers) = verify_headers(lookup_verifier, max_skew, method, path, headers)

if error is not None:
    # Return error or raise exception as needed
```


## Recipe: Verify using Ed25519 public key

```python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

public_key = \
    b'-----BEGIN PUBLIC KEY-----\n' \
    b'MCowBQYDK2VwAyEAe9+zIz+CH9E++J0qiE6aS657qzxsNWIEf2BZcUAQF94=\n' \
    b'-----END PUBLIC KEY-----\n'
public_key = load_pem_public_key(public_key, backend=default_backend())

def verify(sig, d):
    try:
        public_key.verify(sig, d)
    except InvalidSignature:
        return False
    return True

def lookup_verifier(key_id):
    # Could use the supplied key_id to lookup different public keys
    return verify

# method, path, and headers would be taken from the incoming HTTP request
error, (key_id, verified_headers) = verify_headers(lookup_verifier, 10, method, path, headers)
```


## Recipe: Create an Ed25519 public/private key pair

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

private_key = Ed25519PrivateKey.generate()
print(private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))
print(private_key.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
```


# What's implemented

A deliberate subset of the signature algorithm is implemented/enforced:

- the `(request-target)` pseudo-header is required and verified;
- the `created` parameter is required, and the corresponding `(created)` pseudo-header must be signed;
- the `headers` parameter is required;
- the `expires` parameter, if sent, must _not_ correspond to a signed `(expires)` pseudo-header;
- the `algorithm` parameter is ignored if sent.

There are a few places where the implementation is technically, and deliberately, non-conforming.

- The `(created)` pseudo-header: if this is in the future from the server's point of view, even 1 second, according to the spec verification should fail. Instead, there is a configurable maximum time skew that applies to the future as well as the past.

- The `expires` parameter: if this is sent and in the past from the server's point of view, according to the spec verification should fail.

- The `algorithm` parameter: if it's sent but does not match what the server expects, according to the spec verification should fail.

It is assumed that the `(created)` and `(request-target)` pseudo-headers were prepended to the list of real HTTP headers before canonicalisation at the client. This fact only makes a difference in the edge case of real HTTP headers called `(created)` or `(request-target)`.
