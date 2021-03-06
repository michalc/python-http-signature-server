from datetime import datetime
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

from http_signature_client import sign_headers
from http_signature_server import verify_headers


class TestIntegration(unittest.TestCase):

    def test_verifier(self):
        def verify(key_id, sig, data):
            # In a real case, ensure to avoid timing attacks
            return \
                None if key_id != 'cor' else \
                sig == b'cor' and data == correct_signature_input

        now = str(int(datetime.now().timestamp()))
        correct_signature_input =  \
            f'(created): {now}\n' \
            f'(request-target): get /any'.encode('ascii')

        error, creds = verify_headers(verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Unknown keyId')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="aW5j", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Signature does not verify')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, None)
        self.assertEqual(creds, ('cor', ()))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, None)
        self.assertEqual(creds, ('cor', ()))

    def test_skew(self):
        now = str(int(datetime.now().timestamp()) - 11)
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Created skew too large')
        self.assertEqual(creds, (None, None))

        now = str(int(datetime.now().timestamp()) + 15)
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Created skew too large')
        self.assertEqual(creds, (None, None))

    def test_missing_signature(self):
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ())
        self.assertEqual(error, 'Missing signature header')
        self.assertEqual(creds, (None, None))

    def test_invalid_signature(self):
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key=',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key="',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key="d", ',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key=d',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key=4, ',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key=4, ',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key=4, k',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'key=4, k=',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature', 'keyTwo="v1",  keyTwo="v2"',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

    def test_missing_parameters(self):
        now = str(int(datetime.now().timestamp()))
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Missing signature parameter')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="Y29y"',
        ),))
        self.assertEqual(error, 'Missing headers parameter')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Missing created parameter')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Missing keyId parameter')
        self.assertEqual(creds, (None, None))

    def test_repeated_parameters(self):
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'any="something", any="other"',
        ),))
        self.assertEqual(error, 'Repeated parameter')
        self.assertEqual(creds, (None, None))

    def test_missing_required_signed_headers(self):
        now = str(int(datetime.now().timestamp()))
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created)"',
        ),))
        self.assertEqual(error, 'Unsigned (request-target) pseudo-header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(request-target)"',
        ),))
        self.assertEqual(error, 'Unsigned (created) pseudo-header')
        self.assertEqual(creds, (None, None))

    def test_repeated_signed_header(self):
        now = str(int(datetime.now().timestamp()))
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created)"',
        ),))
        self.assertEqual(error, 'Unsigned (request-target) pseudo-header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created) (created)"',
        ),))
        self.assertEqual(error, 'Repeated signed header')
        self.assertEqual(creds, (None, None))

    def test_invalid_created(self):
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created="X", signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Invalid created paramater')
        self.assertEqual(creds, (None, None))

    def test_missing_signed_headers(self):
        now = str(int(datetime.now().timestamp()))
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target) '
            f'ver1 ver2"',
        ),))
        self.assertEqual(error, 'Missing signed ver1 header value')
        self.assertEqual(creds, (None, None))
        sig_val = \
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target) ' \
            f'ver1 ver2"'
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', (
            ('signature', sig_val),
            ('ver1', 'value'),
        ))
        self.assertEqual(error, 'Missing signed ver2 header value')
        self.assertEqual(creds, (None, None))

    def test_subset_of_headers_signed(self):
        now = str(int(datetime.now().timestamp()))

        sig_val = \
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target) ' \
            f'h1 h3"'
        error, creds = verify_headers(always_verify, 10, 'GET', '/any', (
            ('signature', sig_val),
            ('H1', 'value1'),
            ('h2', 'value2'),
            ('h3', 'value3'),
        ))
        self.assertEqual(error, None)
        self.assertEqual(creds, ('cor', (('H1', 'value1'), ('h3', 'value3'))))

    def test_client(self):
        key_id = 'my-key'
        pem_private_key = \
            b'-----BEGIN PRIVATE KEY-----\n' \
            b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n' \
            b'-----END PRIVATE KEY-----\n'

        private_key = load_pem_private_key(
            pem_private_key, password=None, backend=default_backend())

        method = 'post'
        path = '/some-path?a=b&a=c&d=e'
        headers = (
            ('connection', 'close'),
            ('x-custom', 'first  '),
            ('x-custom', '  second'),
            ('(request-target)', 'some-value'),
            ('(created)', 'some-other-value'),
        )
        signed_headers = sign_headers(key_id, private_key.sign, method, path, headers)

        public_key = \
            b'-----BEGIN PUBLIC KEY-----\n' \
            b'MCowBQYDK2VwAyEAe9+zIz+CH9E++J0qiE6aS657qzxsNWIEf2BZcUAQF94=\n' \
            b'-----END PUBLIC KEY-----\n'
        public_key = load_pem_public_key(public_key, backend=default_backend())

        def verify(_, sig, d):
            try:
                public_key.verify(sig, d)
            except InvalidSignature:
                return False
            return True

        error, (key_id, verified_headers) = verify_headers(
            verify, 10, method, path, signed_headers)
        self.assertEqual(error, None)
        self.assertEqual(key_id, 'my-key')
        self.assertEqual(verified_headers, (
            ('x-custom', 'first  '),
            ('x-custom', '  second'),
            ('(request-target)', 'some-value'),
            ('(created)', 'some-other-value'),
        ))

        error, _ = verify_headers(verify, 10, 'not', path, signed_headers)
        self.assertEqual(error, 'Signature does not verify')

        error, _ = verify_headers(verify, 10, method, '/not', signed_headers)
        self.assertEqual(error, 'Signature does not verify')


def always_verify(_, __, ___):
    return True
