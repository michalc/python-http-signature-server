from datetime import datetime
import unittest

from http_signature_server import verify_headers


class TestIntegration(unittest.TestCase):

    def test_verifier(self):
        def lookup_verifier(key_id):
            # In a real case, ensure to avoid timing attacks
            return \
                None if key_id != 'cor' else \
                lambda sig, data: sig == b'cor' and data == correct_signature_input

        now = str(int(datetime.now().timestamp()))
        correct_signature_input =  \
            f'(created): {now}\n' \
            f'(request-target): get /any'.encode('ascii')

        error, creds = verify_headers(lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Unknown keyId')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="aW5j", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Signature does not verify')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, None)
        self.assertEqual(creds, ('cor', ()))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, None)
        self.assertEqual(creds, ('cor', ()))

    def test_skew(self):
        now = str(int(datetime.now().timestamp()) - 11)
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Created skew too large')
        self.assertEqual(creds, (None, None))

        now = str(int(datetime.now().timestamp()) + 15)
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Created skew too large')
        self.assertEqual(creds, (None, None))

    def test_missing_signature(self):
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ())
        self.assertEqual(error, 'Missing signature header')
        self.assertEqual(creds, (None, None))

    def test_invalid_signature(self):
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key=',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key="',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key="d", ',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key=d',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key=4, ',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key=4, ',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key=4, k',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'key=4, k=',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature', 'keyTwo="v1",  keyTwo="v2"',
        ),))
        self.assertEqual(error, 'Invalid signature header')
        self.assertEqual(creds, (None, None))

    def test_missing_parameters(self):
        now = str(int(datetime.now().timestamp()))
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Missing signature parameter')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="Y29y"',
        ),))
        self.assertEqual(error, 'Missing headers parameter')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Missing created parameter')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'created={now}, signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Missing keyId parameter')
        self.assertEqual(creds, (None, None))

    def test_repeated_parameters(self):
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'any="something", any="other"',
        ),))
        self.assertEqual(error, 'Repeated parameter')
        self.assertEqual(creds, (None, None))

    def test_missing_required_signed_headers(self):
        now = str(int(datetime.now().timestamp()))
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created)"',
        ),))
        self.assertEqual(error, 'Unsigned (request-target) pseudo-header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(request-target)"',
        ),))
        self.assertEqual(error, 'Unsigned (created) pseudo-header')
        self.assertEqual(creds, (None, None))

    def test_repeated_signed_header(self):
        now = str(int(datetime.now().timestamp()))
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created)"',
        ),))
        self.assertEqual(error, 'Unsigned (request-target) pseudo-header')
        self.assertEqual(creds, (None, None))

        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="inc", created={now}, signature="Y29y", headers="(created) (created)"',
        ),))
        self.assertEqual(error, 'Repeated signed header')
        self.assertEqual(creds, (None, None))

    def test_invalid_created(self):
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created="X", signature="Y29y", headers="(created) (request-target)"',
        ),))
        self.assertEqual(error, 'Invalid created paramater')
        self.assertEqual(creds, (None, None))

    def test_missing_signed_headers(self):
        now = str(int(datetime.now().timestamp()))
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', ((
            'signature',
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target) '
            f'ver1 ver2"',
        ),))
        self.assertEqual(error, 'Missing signed ver1 header value')
        self.assertEqual(creds, (None, None))
        sig_val = \
            f'keyId="cor", created={now}, signature="Y29y", headers="(created) (request-target) ' \
            f'ver1 ver2"'
        error, creds = verify_headers(always_true_lookup_verifier, 10, 'GET', '/any', (
            ('signature', sig_val),
            ('ver1', 'value'),
        ))
        self.assertEqual(error, 'Missing signed ver2 header value')
        self.assertEqual(creds, (None, None))


def always_true_lookup_verifier(_):
    return lambda _, __: True
