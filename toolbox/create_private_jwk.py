import json

from click import Choice
from click import option
from click import command
from jwcrypto.jwk import JWK


@command
@option('--format', 'output_format', type=Choice(['json', 'pem']), default='json', help='The output format for the private JSON Web Key.')
def cli(output_format: str) -> None:
    '''Creates a private JSON Web Key.'''
    # Todo: Pass key parameters as cli options (e.g. alg, kty, use, ...).
    jwk = JWK.generate(alg='RS256', kty='RSA', use='sig')

    if output_format == 'pem':
        private_key = jwk.export_to_pem(
            private_key=True,
            password=None
        )
        print(private_key.decode())

    else:
        private_key = json.dumps(
            jwk.export_private(as_dict=True),
            indent=4
        )
        print(private_key)


if __name__ == '__main__':
    cli(None)
