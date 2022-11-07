import json
from uuid import uuid4
from typing import Tuple
from pathlib import Path as PathLibPath

from click import Path as ClickPath
from click import command
from click import argument
from jwcrypto.jwk import JWK
from jwcrypto.jwk import JWKSet
from click.exceptions import UsageError # pylint: disable=ungrouped-imports


@command
@argument('jwk', nargs=-1, type=ClickPath(exists=True, dir_okay=False, path_type=PathLibPath))
def cli(jwk: Tuple[PathLibPath]) -> None:
    '''Creates a private JSON Web Key Set from JSON Web Keys.'''
    if not all(x.suffix in ('.json', '.pem') for x in jwk):
        raise UsageError('Only json and pem files are supported.')

    def import_key(path :PathLibPath) -> JWK:
        jwk_instance = JWK()
        if path.suffix == '.json':
            jwk_instance.import_key(**json.loads(path.read_text()))
        else:
            jwk_instance.import_from_pem(path.read_bytes())
        jwk_instance['kid'] = str(uuid4())
        return jwk_instance
    jwks = map(import_key, jwk)

    jwkset = JWKSet()
    for jwk_instance in jwks:
        jwkset.add(jwk_instance)

    private_keys = json.dumps(
        jwkset.export(as_dict=True),
        indent=4
    )
    print(private_keys)


if __name__ == '__main__':
    cli(None)
