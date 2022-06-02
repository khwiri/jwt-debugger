from pathlib import Path
from unittest import TestCase

from jwcrypto.jwk import JWK
from parameterized import parameterized

from tests.helpers import load_public_key
from tests.helpers import load_decoded_token
from tests.helpers import load_encoded_token
from jwt_debugger.decoder import PEM_HEADER_PATTERN
from jwt_debugger.decoder import DecodedToken
from jwt_debugger.decoder import decode_token


class TestPEMRegex(TestCase):
    def test_regex(self):
        pem_path    = Path('.') / 'tests' / 'examples' / 'public_key-example_rsa256.pem'
        pem_content = pem_path.read_text()
        match       = PEM_HEADER_PATTERN.fullmatch(pem_content)
        self.assertTrue(match)


class TestDecodeToken(TestCase):
    def assertDecodedTokenEqual(self, first, second): # pylint: disable=invalid-name
        self.assertEqual(first.header, second.header)
        self.assertEqual(first.payload, second.payload)
        self.assertEqual(first.verified, second.verified)

    @parameterized.expand([
        (
            load_encoded_token('rsa256'),
            load_decoded_token('rsa256'),
        ),
    ])
    def test_decode_without_public_key(self, encoded_token :str, expect :DecodedToken):
        decoded_token = decode_token(encoded_token)
        self.assertDecodedTokenEqual(decoded_token, expect)
        self.assertIsNone(decoded_token.verified)

    @parameterized.expand([
        (
            load_public_key('rsa256'),
            load_encoded_token('rsa256'),
            load_decoded_token('rsa256', verified=True),
        ),
        (
            load_public_key('rsa256'),
            load_encoded_token('rsa256_with_invalid_signature'),
            load_decoded_token('rsa256', verified=False),
        ),
        (
            load_public_key('rsa256_with_invalid_modulus'),
            load_encoded_token('rsa256'),
            load_decoded_token('rsa256', verified=False),
        )
    ])
    def test_decode_with_public_key(self, public_key :JWK, encoded_token :str, expect :DecodedToken):
        decoded_token = decode_token(encoded_token, public_key)
        self.assertDecodedTokenEqual(decoded_token, expect)
        self.assertIsNotNone(decoded_token.verified)
