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
