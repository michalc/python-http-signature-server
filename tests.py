from datetime import datetime
import unittest

from http_signature_server import verify_headers


class TestIntegration(unittest.TestCase):

    def test_unknown_id(self):
        def lookup_verifier(_):
            return None

        now = str(int(datetime.now().timestamp()))
        headers = ((
            'signature',
            f'keyId="any", created={now}, signature="any", headers="(created) (request-target)"',
        ),)
        error, creds = verify_headers(lookup_verifier, 10, 'GET', '/any', headers)

        self.assertEqual(error, 'Unknown keyId')
        self.assertEqual(creds, None)
