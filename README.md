# JWT Debugger

[![License](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/khwiri/jwt-debugger)
[![Test](https://github.com/khwiri/jwt-debugger/actions/workflows/test.yml/badge.svg)](https://github.com/khwiri/jwt-debugger/actions/workflows/test.yml)
[![Lint](https://github.com/khwiri/jwt-debugger/actions/workflows/lint.yml/badge.svg)](https://github.com/khwiri/jwt-debugger/actions/workflows/lint.yml)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://github.com/khwiri/jwt-debugger)

**JWT Debugger** is a command-line interface inspired by [jwt.io](https://jwt.io)
that can be used for decoding and verifying JSON Web Tokens. Under the hood,
[JWCrypto](https://jwcrypto.readthedocs.io/en/latest/) is doing the heavy lifting
so that the token can be locally introspected.

![Example Usage](./assets/example_usage.png)

## Installing

Install with [pip](https://pip.pypa.io/en/stable).

*Note: Passing --editable so that pip freeze produces usable requirements.*

```
pip install --editable git+https://github.com/khwiri/jwt-debugger.git@main#egg=jwt-debugger
```

Install with [pipenv](https://pipenv.pypa.io/en/latest).

```
pipenv install git+https://github.com/khwiri/jwt-debugger.git@main#egg=jwt-debugger
```

## Usage

```
jwt-debugger --help
Usage: jwt-debugger [OPTIONS] TOKEN

Options:
  --public-key FILENAME     JSON Web Key in JSON or PEM format for signature
                            verification.
  --oidc-provider-url TEXT  OpenID Connect Provider URL where JSON Web Key Set
                            can be pulled for signature verification.
  --format [pretty|json]    Output format
  --help                    Show this message and exit.
```

### Examples

Simply pass a JSON Web Token to have it decoded.

```
jwt-debugger TOKEN
```

Tokens can also be read from standard input. The following example uses
[create_token.py](toolbox/create_token.py) to generate a token.

```
python toolbox/create_token.py --jwk toolbox/example_private_key_rs256.json toolbox/example_payload.json | jwt-debugger
```

If you have a JSON Web Key then that can be used to verify whether the token has
been tampered with by checking the signature. JSON Web Keys can be formatted as
JSON or PEM.

```
jwt-debugger --public-key jwk.json TOKEN
```

```
jwt-debugger --public-key jwk.pem TOKEN
```

Alternatively, JSON Web Keys can be used from OpenID Connect Providers. This can
be accomplished by using the `--oidc-provider-url` argument and a url referencing
[OpenID Connect Provider Configuration Information](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).

```
jwt-debugger --oidc-provider-url https://accounts.google.com/.well-known/openid-configuration TOKEN
```

If you're using [IdentityServer4](https://github.com/IdentityServer/IdentityServer4)
then a direct url to the JSON Web Key Set can be used.

```
jwt-debugger --oidc-provider-url https://demo.identityserver.io/.well-known/openid-configuration/jwks TOKEN
```

Additionally, tokens can be decoded as JSON so that they can be piped to other commands. Here's
an example using [jq](https://stedolan.github.io/jq/) to extract the `name` property from the `payload` found in [toolbox/example_payload.json](./toolbox/example_payload.json).

```
jwt-debugger --format json TOKEN | jq ".payload.name"
```

## Contributing

For guidance on setting up a development environment and how to make a contribution,
see the [contributing guidelines](./CONTRIBUTING.md).
