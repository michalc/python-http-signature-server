# http-signature-server

HTTP server agnostic Python implementation of the server side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00), with [cryptography](https://github.com/pyca/cryptography) the only dependency other than the Python standard library.

A deliberate subset of the signature algorithm is implemented/enforced:

- the `(request-target)` pseudo-header is required and verified;
- the `created` parameter is required and verified, with a configurable maximum skew;
- the `headers` parameter is required and verified;
- the `expires` parameter is ignored if sent;
- the `algorithm` parameter is ignored if sent.

There are a few places where the implementation is technically, and deliberately, non-conforming.

- The `(created)` pseudo-header: if this is in the future from the server's point of view, even 1 second, according to the spec verification should fail.

- The `expires` parameter: if this is sent and in the past from the server's point of view, according to the spec verification should fail.

- The `algorithm` parameter: if it's sent but does not match what the server expects, according to the spec verification should fail.

> This is a work in progress. This README serves as a rough design spec.


## Usage

```python
from http_signature_server import verify

def get_verifier(key_id):
    # If the key_id is found, return a callable that takes the signature and key_id and returns a bool
    # If the key_id isn't known, return None

error, (key_id, verified_headers) = verify(get_verifier, max_skew, method, path, headers)
```
