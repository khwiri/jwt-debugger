import json
from typing import Dict
from typing import Union
from typing import Optional
from pathlib import Path

from jwcrypto.jwk import JWK
from jwcrypto.jwk import JWKSet

from jwt_debugger.decoder import DecodedToken


class UnsupportedPublicKeyFormat(Exception):
    pass


def get_public_key_path(example: Union[int, str], key_format: str = None) -> Path:
    key_format = 'json' if key_format is None else key_format
    if key_format not in ('json', 'pem'):
        raise UnsupportedPublicKeyFormat()

    return Path('.') / 'tests' / 'examples' / f'public_key-example_{example}.{key_format}'


def load_public_key(example: Union[int, str], key_format: str = None) -> JWK:
    key_format = 'json' if key_format is None else key_format
    if key_format not in ('json', 'pem'):
        raise UnsupportedPublicKeyFormat()

    example_key_content = get_public_key_path(example, key_format).read_text()

    if key_format == 'json':
        return JWK(**json.loads(example_key_content))

    if key_format == 'pem':
        return JWK.from_pem(example_key_content)


def get_public_keyset_path(example: Union[int, str]) -> Path:
    return Path('.') / 'tests' / 'examples' / f'public_keyset-example_{example}.json'


def load_public_keyset(example: Union[int, str]) -> JWKSet:
    example_key_content = get_public_keyset_path(example).read_text()
    return JWKSet.from_json(example_key_content)


def load_encoded_token(example: Union[int, str]) -> str:
    example_file_name = f'encoded_token-example_{example}.txt'
    example_token_path = Path('.') / 'tests' / 'examples' / example_file_name

    return example_token_path.read_text().strip() # stripping trailing newline characters


def load_decoded_token_as_json(example: Union[int, str]) -> Dict:
    example_file_name = f'decoded_token-example_{example}.json'
    example_token_path = Path('.') / 'tests' / 'examples' / example_file_name

    with example_token_path.open() as f:
        return json.load(f)


def load_decoded_token(example: Union[int, str], verified: Optional[bool] = None) -> DecodedToken:
    token_as_json = load_decoded_token_as_json(example)
    return DecodedToken(
        token='faux-token',
        header=token_as_json.get('header',  {}),
        payload=token_as_json.get('payload', {}),
        verified=verified
    )
