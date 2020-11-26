import json
from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import MagicMock
from unittest.mock import patch

from parameterized import parameterized

from jwt_debugger.decoder import PEM_HEADER_PATTERN
from jwt_debugger.decoder import decode_token
from jwt_debugger.decoder import load_jwk_from_file
from jwt_debugger.decoder import resolve_jwks_uri_from_open_id_connect_provider


PUBLIC_KEY_PEM = '''
------BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkXCpXa9LAGGXRiYIcs44
adFdfPIjqYAaHgtKVzHC2cGvMn2wuG56uwNP4VsLmZ2qNNeazUofRWpPa/jlwSKJ
GEDfuD2M3TdO38XqOPHnbDUW+b8KS/TMMpVW/0HIHV9t7VQSa7NZA7wmWgdQBBJ7
39d+ERubDOjtTfM/QH961zVKnf84cQ0vnVuYwn0kK+frUS0PPujxOWcOT7EAmowH
6vZ0Ey9l+Z+l+y9HcDKgZFVmHvbTZCiK48k57fEtw4b/MMs6i/3xFoff5DYkdJF6
vo8jxa5m5dUUCOyeGl5e4BVAliSg0by7K/Clkdo7E5UGOSN4vpP29UJ5lK0KOhCL
qQIDAQAB
-----END PUBLIC KEY-----
'''


PUBLIC_KEY_JSON = {
    'kty' : 'RSA',
    'e'   : 'AQAB',
    'use' : 'sig',
    'alg' : 'RS256',
    'n'   : 'kXCpXa9LAGGXRiYIcs44adFdfPIjqYAaHgtKVzHC2cGvMn2wuG56uwNP4VsLmZ2qNNeazUofRWpPa_jlwSKJGEDfuD2M3TdO38XqOPHnbDUW-b8KS_TMMpVW_0HIHV9t7VQSa7NZA7wmWgdQBBJ739d-ERubDOjtTfM_QH961zVKnf84cQ0vnVuYwn0kK-frUS0PPujxOWcOT7EAmowH6vZ0Ey9l-Z-l-y9HcDKgZFVmHvbTZCiK48k57fEtw4b_MMs6i_3xFoff5DYkdJF6vo8jxa5m5dUUCOyeGl5e4BVAliSg0by7K_Clkdo7E5UGOSN4vpP29UJ5lK0KOhCLqQ',
}


ENCODED_TOKEN         = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJNYXJ0eSBCeXJkZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.duvlCY0mXz6ZlyvOwfNh6EnM7HmKVNSouNRi8r-0sQuNhO6umrWhPIAm3ZH70eOr3qwpwi3A73P05E277zuBaXd2NWriqpos4T9gp6_XtK8tKzpEqA90tjYdSYBpgGaecD9mJ4siB1XSzP2bfUv3xyX65BylDWgd0aJiImpBjB9TPU0_9lF-kgF6PCFTuyDjalP19QgrP3SwDrSHSKw2ihGWC2kXiaJ5YkbOYVzwAGXia34dufR_LA4rN7WRGbVWL58ri62HrB_HNJDI21T-gx_b78G3BavmGw5unxTe54UGHFtoY8OAeEvkBeLaliOusr6QjR-63JB8P2KJxQ6TUA'
DECODED_TOKEN_HEADER  = {'typ': 'JWT', 'alg': 'RS256'}
DECODED_TOKEN_PAYLOAD = {'sub': '1234567890', 'name': 'Marty Byrde', 'iat': 1516239022}


class TestResolveJWKSURIFromOpenIDConnectProvider(TestCase):
    def setUp(self):
        self._faux_jwks_uri = 'faux-uri'
        self._mock_configuration_response = Mock()
        self._mock_configuration_response.json.return_value = {'jwks_uri': self._faux_jwks_uri}

    def test_identity_server_jwks_uri(self):
        provider_url  = 'https://demo.identityserver.io/.well-known/openid-configuration/jwks'
        with patch('requests.get', return_value=self._mock_configuration_response) as mock_requests_get:
            resolved_url = resolve_jwks_uri_from_open_id_connect_provider(provider_url)
            mock_requests_get.assert_not_called()
            self.assertEqual(provider_url, resolved_url)

    def test_provider_url_converts_to_configuration_url(self):
        provider_url  = 'https://accounts.google.com'
        with patch('requests.get', return_value=self._mock_configuration_response) as mock_requests_get:
            resolve_jwks_uri_from_open_id_connect_provider(provider_url)
            mock_requests_get.assert_called_with(f'{provider_url}/.well-known/openid-configuration')

    def test_provider_url_is_configuration_url(self):
        provider_url  = 'https://accounts.google.com/.well-known/openid-configuration'
        with patch('requests.get', return_value=self._mock_configuration_response) as mock_requests_get:
            resolve_jwks_uri_from_open_id_connect_provider(provider_url)
            mock_requests_get.assert_called_with(provider_url)

    def test_provider_url_resolves_to_jwks_uri(self):
        provider_url  = 'https://accounts.google.com/.well-known/openid-configuration'
        with patch('requests.get', return_value=self._mock_configuration_response):
            jwks_uri = resolve_jwks_uri_from_open_id_connect_provider(provider_url)
            self.assertEqual(jwks_uri, self._faux_jwks_uri)

    def test_configuration_does_not_include_jwks_uri(self):
        provider_url  = 'https://accounts.google.com/.well-known/openid-configuration'
        mock_response = Mock()
        mock_response.json.return_value = {}
        with patch('requests.get', return_value=mock_response), self.assertRaises(KeyError) as raise_context:
            resolve_jwks_uri_from_open_id_connect_provider(provider_url)
        self.assertEqual(
            str(raise_context.exception),
            f"'OpenID Connect Configuration({provider_url}) does not contain jwks_uri endpoint.'"
        )


class TestPEMRegex(TestCase):
    def test_regex(self):
        match = PEM_HEADER_PATTERN.fullmatch(PUBLIC_KEY_PEM)
        self.assertTrue(match)


class TestDecodeToken(TestCase):
    @parameterized.expand([
        (ENCODED_TOKEN,            True ),
        (ENCODED_TOKEN[:-1] + 'a', False),
    ])
    def test_decode(self, token, signature_verified):
        mock_key = Mock()
        mock_key.read.return_value = json.dumps(PUBLIC_KEY_JSON)

        jwk = load_jwk_from_file(mock_key)
        decoded_token = decode_token(token, jwk)

        self.assertEqual(decoded_token.header,   DECODED_TOKEN_HEADER)
        self.assertEqual(decoded_token.payload,  DECODED_TOKEN_PAYLOAD)
        self.assertEqual(decoded_token.verified, signature_verified)

    def test_decode_with_invalid_public_key(self):
        mock_key = Mock()
        mock_key.read.return_value = json.dumps({**PUBLIC_KEY_JSON, 'n': 'faux'})

        jwk = load_jwk_from_file(mock_key)
        decoded_token = decode_token(ENCODED_TOKEN, jwk)

        self.assertEqual(decoded_token.header,  DECODED_TOKEN_HEADER)
        self.assertEqual(decoded_token.payload, DECODED_TOKEN_PAYLOAD)
        self.assertFalse(decoded_token.verified)

    def test_decode_without_public_key(self):
        decoded_token = decode_token(ENCODED_TOKEN, public_key=None)
        self.assertEqual(decoded_token.header,  DECODED_TOKEN_HEADER)
        self.assertEqual(decoded_token.payload, DECODED_TOKEN_PAYLOAD)
        self.assertFalse(decoded_token.verified)
