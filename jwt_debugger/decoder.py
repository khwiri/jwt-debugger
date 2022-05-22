import re
import json
from io import TextIOWrapper
from typing import Dict
from typing import Union
from typing import Optional
from dataclasses import dataclass

import requests
from jwcrypto.jwk import JWK
from jwcrypto.jwk import JWKSet
from jwcrypto.jws import InvalidJWSSignature
from jwcrypto.jwt import JWT


@dataclass
class DecodedToken:
    token    :str
    header   :Dict
    payload  :Dict
    verified :Optional[bool] # Signature Verification will be None for tokens decoded without public keys


def decode_token(token :str, public_key :Optional[Union[JWK, JWKSet]] =None) -> DecodedToken:
    try:
        jwt = JWT(jwt=token, key=public_key)

    except InvalidJWSSignature:
        jwt = JWT(jwt=token)
        verified = False

    else:
        verified = None if public_key is None else True

    return DecodedToken(
        token,
        json.loads(jwt.token.objects.get('protected')),
        json.loads(jwt.token.objects.get('payload', b'').decode()),
        verified
    )


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
