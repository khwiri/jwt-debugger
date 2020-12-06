import sys
from io import TextIOWrapper
from typing import Union
from typing import Optional
from functools import partial

from rich import print  # pylint: disable=redefined-builtin
from click import File
from click import Choice
from click import option
from click import command
from click import argument
from click.exceptions import UsageError

from jwt_debugger.decoder import decode_token
from jwt_debugger.decoder import load_jwk_from_file
from jwt_debugger.decoder import load_jwkset_from_oidc_url
from jwt_debugger.decoder import resolve_jwks_uri_from_open_id_connect_provider


@command()
@option('--public-key', type=File(), help='JSON Web Key in JSON or PEM format for signature verification.')
@option('--oidc-provider-url', help='OpenID Connect Provider URL where JSON Web Key Set can be pulled for signature verification.')
@argument('token', required=True)
def cli(token :str, public_key :Optional[TextIOWrapper] =None, oidc_provider_url :str =None) -> None:
    if all([public_key, oidc_provider_url]):
        raise UsageError('The following options can not be used together (--public-key, --oidc-provider-url).')

    token_parts = token.split('.')
    if len(token_parts) != 3:
        raise ValueError('Token must consist of a header, payload, and signature all separated by periods.')

    if any([public_key, oidc_provider_url]):
        if public_key is not None:
            load_public_key_ = partial(load_jwk_from_file, public_key)

        else:
            jwks_uri = resolve_jwks_uri_from_open_id_connect_provider(oidc_provider_url)
            load_public_key_ = partial(load_jwkset_from_oidc_url, jwks_uri)

        decode_token_ = partial(decode_token, public_key=load_public_key_())

    else:
        decode_token_ = partial(decode_token, public_key=None)

    decoded_token = decode_token_(token)

    print(decoded_token)

    if decoded_token.verified is False:
        sys.exit(1)
