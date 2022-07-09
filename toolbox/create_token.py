import json
from io import TextIOWrapper
from typing import Optional
from pathlib import Path as PathLibPath

from click import File
from click import Path as ClickPath
from click import option
from click import command
from click import argument
from jwcrypto.jwk import JWK
from jwcrypto.jwk import JWKSet
from jwcrypto.jwt import JWT
from click.exceptions import UsageError
from click.exceptions import ClickException


def open_jwk(jwk_path :PathLibPath) -> JWK:
    if jwk_path.suffix not in ('.json', '.pem'):
        raise ClickException('Only json and pem files are supported.')

    if jwk_path.suffix == '.json':
        jwk = JWK.from_json(jwk_path.read_text())

    else:
        jwk = JWK.from_pem(jwk_path.read_bytes())

    return jwk


def get_jwk_from_jwkset(jwkset_path :PathLibPath, kid :Optional[str] =None) -> Optional[JWK]:
    jwkset = JWKSet.from_json(jwkset_path.read_text())
    keys   = list(jwkset['keys'])

    if not keys:
        raise ClickException(f'JWKSet from Path({jwkset_path}) does not contain any keys.')

    if kid is None:
        return keys.pop(0)

    jwk = next(filter(lambda x: x.get('kid') == kid, keys), None)
    if jwk is None:
        raise ClickException(f'JWKSet from Path({jwkset_path}) does not contain a key with kid({kid}).')

    return jwk


@command()
@option('--jwk', 'jwk_path', type=ClickPath(exists=True, dir_okay=False, path_type=PathLibPath), help='Private JSON Web Key in JSON or PEM format for signing.')
@option('--jwkset', 'jwkset_path', type=ClickPath(exists=True, dir_okay=False, path_type=PathLibPath), help='Private JSON Web Key Set for signing.')
@option('--kid', type=str, help='Unique identifier for a key to use from a JSON Web Key Set.')
@argument('payload', type=File(), required=True)
def cli(payload :TextIOWrapper, jwk_path :Optional[PathLibPath] =None, jwkset_path :Optional[PathLibPath] =None, kid :Optional[str] =None) -> None:
    '''Creates an encoded JSON Web Token.'''
    if all([jwk_path, jwkset_path]):
        raise UsageError('The following options can not be used together (--jwk, --jwkset).')

    if jwk_path is not None:
        jwk = open_jwk(jwk_path)

    elif jwkset_path is not None:
        jwk = get_jwk_from_jwkset(jwkset_path, kid)

    else:
        raise UsageError('Must provide either --jwk or --jwkset options.')

    algorithm = jwk.get('alg', 'RS256')
    header    = {'typ': 'JWT', 'alg': algorithm}
    if jwkset_path:
        header['kid'] = jwk.get('kid')

    payload = json.load(payload)
    jwt     = JWT(header=header, claims=payload)

    jwt.make_signed_token(jwk)
    token = jwt.serialize()
    print(f'Token: {token}')


if __name__ == '__main__':
    cli(None, None)
