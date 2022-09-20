import json
from json import JSONDecodeError
from unittest import TestCase
from functools import partial
from unittest.mock import patch

from click.testing import CliRunner
from click.exceptions import UsageError

from tests.helpers import load_public_key
from tests.helpers import load_encoded_token
from tests.helpers import load_public_keyset
from tests.helpers import get_public_key_path
from tests.helpers import load_decoded_token_as_json
from jwt_debugger.command import cli


OIDC_PROVIDER_URL = 'https://accounts.google.com/.well-known/openid-configuration'


class TestCLI(TestCase):
    def setUp(self):
        runner = CliRunner()
        self.invoke_cli = partial(runner.invoke, cli)

    def test_public_key_and_oidc_provider_url(self):
        token           = load_encoded_token('rsa256')
        public_key_path = get_public_key_path('rsa256')

        result = self.invoke_cli(['--public-key', public_key_path, '--oidc-provider-url', OIDC_PROVIDER_URL, token])
        self.assertIn(
            'Error: The following options can not be used together (--public-key, --oidc-provider-url).',
            result.output
        )
        self.assertEqual(UsageError.exit_code, result.exit_code)

    def test_malformed_token(self):
        result = self.invoke_cli('MALFORMED-TOKEN')
        self.assertIn(
            'Error: Token must consist of a header, payload, and signature all separated by periods.',
            result.output
        )
        self.assertEqual(UsageError.exit_code, result.exit_code)

    def test_decode_token_with_public_key(self):
        token           = load_encoded_token('rsa256')
        public_key      = load_public_key('rsa256')
        public_key_path = get_public_key_path('rsa256')

        with patch('jwt_debugger.command.load_jwk_from_file', return_value=public_key) as load_jwk_from_file_mock:
            result = self.invoke_cli(['--public-key', public_key_path, token])
            load_jwk_from_file_mock.assert_called_once()
            self.assertIn('Signature Verified', result.output)
            self.assertEqual(0, result.exit_code)

    def test_decode_token_with_oidc_provider_url(self):
        token      = load_encoded_token('rsa256_kid_2')
        public_key = load_public_keyset('rsa256')

        with patch('jwt_debugger.command.load_jwkset_from_oidc_url', return_value=public_key) as load_jwkset_from_oidc_url_mock:
            result = self.invoke_cli(['--oidc-provider-url', OIDC_PROVIDER_URL, token])
            load_jwkset_from_oidc_url_mock.assert_called_once()
            self.assertIn('"kid": "2"', result.output)
            self.assertIn('Signature Verified', result.output)
            self.assertEqual(0, result.exit_code)

    def test_decode_token_with_invalid_signature(self):
        token           = load_encoded_token('rsa256_with_invalid_signature')
        public_key      = load_public_key('rsa256')
        public_key_path = get_public_key_path('rsa256')

        with patch('jwt_debugger.command.load_jwk_from_file', return_value=public_key) as load_jwk_from_file_mock:
            result = self.invoke_cli(['--public-key', public_key_path, token])
            load_jwk_from_file_mock.assert_called_once()
            self.assertIn('Invalid Signature', result.output)
            self.assertEqual(1, result.exit_code)

    def test_decode_token_from_stdin(self):
        token           = load_encoded_token('rsa256')
        public_key      = load_public_key('rsa256')
        public_key_path = get_public_key_path('rsa256')

        with patch('jwt_debugger.command.load_jwk_from_file', return_value=public_key):
            result = self.invoke_cli(['--public-key', public_key_path], input=token)
            self.assertIn('Signature Verified', result.output)
            self.assertEqual(0, result.exit_code)

    def test_decode_token_with_format_as_json(self):
        token           = load_encoded_token('rsa256')
        public_key      = load_public_key('rsa256')
        public_key_path = get_public_key_path('rsa256')

        expect_decoded_token = load_decoded_token_as_json('rsa256')

        with patch('jwt_debugger.command.load_jwk_from_file', return_value=public_key):
            result = self.invoke_cli(['--public-key', public_key_path, '--format', 'json', token])

            try:
                decoded_token = json.loads(result.output)
            except JSONDecodeError:
                decoded_token = None

            self.assertEqual(decoded_token, expect_decoded_token)
            self.assertEqual(0, result.exit_code)

    def test_decode_token_with_format_as_pretty(self):
        token           = load_encoded_token('rsa256')
        public_key      = load_public_key('rsa256')
        public_key_path = get_public_key_path('rsa256')

        with patch('jwt_debugger.command.load_jwk_from_file', return_value=public_key):
            result = self.invoke_cli(['--public-key', public_key_path, '--format', 'pretty', token])
            self.assertIn('Encoded Token', result.output)
            self.assertIn('Decoded Token', result.output)
            self.assertIn('Signature Verified', result.output)
            self.assertEqual(0, result.exit_code)
