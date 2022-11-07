import json
from pathlib import Path as PathLibPath

from click import Path as ClickPath
from click import command
from click import argument
from jwcrypto.jwk import JWKSet
from click.exceptions import UsageError # pylint: disable=ungrouped-imports


@command
@argument('jwkset', type=ClickPath(exists=True, dir_okay=False, path_type=PathLibPath))
def cli(jwkset: PathLibPath) -> None:
    '''Exports public keys from JSON Web Key Set.'''
    if jwkset.suffix != '.json':
        raise UsageError('Only json files are supported.')

    jwkset_instance = JWKSet.from_json(jwkset.read_text())

    public_key = json.dumps(
        jwkset_instance.export(private_keys=False, as_dict=True),
        indent=4
    )
    print(public_key)


if __name__ == '__main__':
    cli(None)
