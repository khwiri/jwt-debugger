from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import patch

from parameterized import parameterized

from jwt_debugger.decoder import resolve_jwks_uri_from_oidc_provider


class TestOIDCProvider(TestCase):
    def setUp(self):
        self._faux_jwks_uri = 'faux-uri'
        self._mock_configuration_response = Mock()
        self._mock_configuration_response.json.return_value = {'jwks_uri': self._faux_jwks_uri}

    @parameterized.expand([
        (
            'https://example.com',
            'https://example.com/.well-known/openid-configuration',
        ),
        (
            'https://example.com/issuer1',
            'https://example.com/issuer1/.well-known/openid-configuration',
        ),
        (
            'https://example.com/issuer1/',
            'https://example.com/issuer1/.well-known/openid-configuration',
        ),
    ])
    def test_jwks_from_provider_url(self, provider_url: str, configuration_url: str):
        with patch('requests.get', return_value=self._mock_configuration_response) as mock_requests_get:
            jwks_uri = resolve_jwks_uri_from_oidc_provider(provider_url)
            mock_requests_get.assert_called_with(configuration_url)
            self.assertEqual(jwks_uri, self._faux_jwks_uri)

    def test_configuration_does_not_include_jwks_uri(self):
        provider_url = 'https://example.com/.well-known/openid-configuration'
        mock_response = Mock()
        mock_response.json.return_value = {}
        with patch('requests.get', return_value=mock_response), self.assertRaises(KeyError) as raise_context:
            resolve_jwks_uri_from_oidc_provider(provider_url)

        self.assertEqual(
            str(raise_context.exception),
            f"'OpenID Connect Configuration({provider_url}) does not contain jwks_uri endpoint.'"
        )

    def test_identity_server_jwks_uri(self):
        jwks_uri = 'https://demo.identityserver.io/.well-known/openid-configuration/jwks'
        with patch('requests.get', return_value=self._mock_configuration_response) as mock_requests_get:
            jwks_uri_resolved = resolve_jwks_uri_from_oidc_provider(jwks_uri)
            mock_requests_get.assert_not_called()
            self.assertEqual(jwks_uri_resolved, jwks_uri)
