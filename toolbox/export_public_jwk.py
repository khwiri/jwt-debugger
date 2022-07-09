import json
from pathlib import Path as PathLibPath

from click import Path as ClickPath
from click import command
from click import argument
from jwcrypto.jwk import JWK
from click.exceptions import UsageError # pylint: disable=ungrouped-imports


@command
@argument('jwk', type=ClickPath(exists=True, dir_okay=False, path_type=PathLibPath))
def cli(jwk :PathLibPath) -> None:
    '''Exports public key from JSON Web Key with support for JSON or PEM files.'''
    if jwk.suffix not in ('.json', '.pem'):
        raise UsageError('Only json and pem files are supported.')

    jwk_instance = JWK()
    if jwk.suffix == '.json':
        jwk_instance.import_key(**json.loads(jwk.read_text()))

    else:
        jwk_instance.import_from_pem(jwk.read_bytes())

    public_key = json.dumps(
        jwk_instance.export_public(as_dict=True),
        indent=4
    )
    print(public_key)


if __name__ == '__main__':
    cli(None)
