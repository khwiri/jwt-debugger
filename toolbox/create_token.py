import json

from click import File
from click import option
from click import command
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT


def extract_signing_algorithm(key :JWK) -> str:
    key_export = json.loads(key.export())
    algorithm  = key_export.get('alg')
    if algorithm is None:
        raise ValueError('JSON Web Key Missing Signing Algorithm')
    return algorithm


@command()
@option('--private-key', type=File(), required=True)
@option('--payload',     type=File(), required=True)
def cli(private_key :File, payload :File) -> None:
    private_key = JWK(**json.load(private_key))
    signing_algorithm = extract_signing_algorithm(private_key)

    header  = {'typ': 'JWT', 'alg': signing_algorithm}
    payload = json.load(payload)
    jwt     = JWT(header=header, claims=payload)

    jwt.make_signed_token(private_key)
    token = jwt.serialize()
    print(f'Token: {token}')


if __name__ == '__main__':
    cli(None, None)
