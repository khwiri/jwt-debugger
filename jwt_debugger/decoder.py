import re
import json
from io import TextIOWrapper
from typing import Dict
from typing import Union
from typing import Optional
from functools import partial
from dataclasses import dataclass

import requests
from rich.text import Text
from rich.emoji import Emoji
from rich.table import Table
from jwcrypto.jwk import JWK
from jwcrypto.jwk import JWKSet
from jwcrypto.jws import InvalidJWSSignature
from jwcrypto.jwt import JWT
from rich.console import RenderResult


HEADER_COLOR         = '#fb015b'
PAYLOAD_COLOR        = '#d63aff'
SIGNATURE_COLOR      = '#00b9f1'
DELIMITER_COLOR      = '#000000'
SIGANTURE_VALID_COLOR   = SIGNATURE_COLOR
SIGNATURE_INVALID_COLOR = '#ff0000'
SIGNATURE_SKIP_COLOR    = '#aaaaaa'


pretty_json_dumps_ = partial(json.dumps, indent=4)


@dataclass
class DecodedToken:
    token    :str
    header   :Dict
    payload  :Dict
    verified :Optional[bool] # Signature Verification will be None for tokens decoded without public keys

    def __rich_console__(self, *args, **kwargs) -> RenderResult:
        yield self._render_encoded_token_table()
        yield self._render_decoded_token_table()

    def _render_encoded_token_table(self):
        header, payload, signature = self.token.split('.')

        text = Text(overflow='fold')
        text.append(header,    style=HEADER_COLOR)
        text.append('.',       style=DELIMITER_COLOR)
        text.append(payload,   style=PAYLOAD_COLOR)
        text.append('.',       style=DELIMITER_COLOR)
        text.append(signature, style=SIGNATURE_COLOR)

        table = Table(expand=True)
        table.add_column('Encoded Token')
        table.add_row(text)

        return table

    def _render_decoded_token_table(self):
        table = Table(expand=True, leading=1)
        table.add_column('Decoded Token')

        header_text = Text(overflow='fold')
        header_text.append('Header\n', style=HEADER_COLOR)
        header_text.append(pretty_json_dumps_(self.header), style=HEADER_COLOR)
        table.add_row(header_text)

        payload_text = Text(overflow='fold')
        payload_text.append('Payload\n', style=PAYLOAD_COLOR)
        payload_text.append(pretty_json_dumps_(self.payload), style=PAYLOAD_COLOR)
        table.add_row(payload_text)

        if self.verified is True:
            signature_text = Text(
                Emoji.replace('Signature Verified :blue_heart:'),
                style=SIGANTURE_VALID_COLOR
            )

        elif self.verified is False:
            signature_text = Text(
                Emoji.replace('Invalid Signature :skull:'),
                style=SIGNATURE_INVALID_COLOR
            )

        else:
            signature_text = Text(
                Emoji.replace('Skipped Signature Verification :eyes:'),
                style=SIGNATURE_SKIP_COLOR
            )

        table.add_row(signature_text)

        return table


def decode_token(token :str, public_key :Optional[Union[JWK, JWKSet]] =None) -> DecodedToken:
    try:
        jwt = JWT(jwt=token, key=public_key)

    except InvalidJWSSignature:
        jwt = JWT(jwt=token)
        verified = False

    else:
        verified = None if public_key is None else True

    decoded_token = DecodedToken(
        token    = token,
        header   = json.loads(jwt.token.objects.get('protected')),
        payload  = json.loads(jwt.token.objects.get('payload', b'').decode()),
        verified = verified
    )
    return decoded_token


PEM_HEADER_PATTERN = re.compile('.*-----BEGIN .+-----.+-----END .+-----.*', flags=re.DOTALL)
def load_jwk_from_file(key :TextIOWrapper) -> JWK:
    content = key.read()
    if PEM_HEADER_PATTERN.fullmatch(content):
        key = JWK.from_pem(content.encode())

    else:
        key = JWK(**json.loads(content))

    return key


def load_jwkset_from_oidc_url(url :str) -> JWKSet:
    '''Load JSON Web Key Set from OpenID Connect JWKS endpoint'''
    response = requests.get(url)
    response.raise_for_status()

    key_set = JWKSet.from_json(response.text)
    return key_set


def resolve_jwks_uri_from_oidc_provider(provider_url :str) -> str:
    '''Resolve JWKS Endpoint from OpenID Connect Provider url'''
    # Default IdentityServer4 jwks url
    #  reference: https://github.com/IdentityServer/IdentityServer4
    #  example:   https://demo.identityserver.io/.well-known/openid-configuration
    if provider_url.endswith('/.well-known/openid-configuration/jwks'):
        return provider_url

    # OpenID Provider Configuration
    #  reference: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    if not provider_url.endswith('/.well-known/openid-configuration'):
        provider_url = provider_url[:-1] if provider_url.endswith('/') else provider_url
        configuration_url = f'{provider_url}/.well-known/openid-configuration'

    else:
        configuration_url = provider_url

    configuration_response = requests.get(configuration_url)
    configuration_response.raise_for_status()

    configuration = configuration_response.json()
    jwks_uri = configuration.get('jwks_uri')
    if jwks_uri is None:
        raise KeyError(f'OpenID Connect Configuration({configuration_url}) does not contain jwks_uri endpoint.')

    return jwks_uri
