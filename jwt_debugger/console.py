import json
from typing import Dict
from typing import Optional
from functools import partial
from dataclasses import dataclass

from rich.text import Text
from rich.emoji import Emoji
from rich.table import Table
from rich.console import RenderResult


HEADER_COLOR = '#fb015b'
PAYLOAD_COLOR = '#d63aff'
SIGNATURE_COLOR = '#00b9f1'
DELIMITER_COLOR = '#000000'
SIGANTURE_VALID_COLOR = SIGNATURE_COLOR
SIGNATURE_INVALID_COLOR = '#ff0000'
SIGNATURE_SKIP_COLOR = '#aaaaaa'


pretty_json_dumps_ = partial(json.dumps, indent=4)


@dataclass
class PrettyDecodedToken:
    token    :str
    header   :Dict
    payload  :Dict
    verified :Optional[bool] # Signature Verification will be None for tokens decoded without public keys

    def __rich_console__(self, *args, **kwargs) -> RenderResult:
        yield self._render_encoded_token_table()
        yield self._render_decoded_token_table()

    def _render_encoded_token_table(self):
        header, payload, signature = self.token.split('.')

        text = Text(overflow='fold')
        text.append(header, style=HEADER_COLOR)
        text.append('.', style=DELIMITER_COLOR)
        text.append(payload, style=PAYLOAD_COLOR)
        text.append('.', style=DELIMITER_COLOR)
        text.append(signature, style=SIGNATURE_COLOR)

        table = Table(expand=True)
        table.add_column('Encoded Token')
        table.add_row(text)

        return table

    def _render_decoded_token_table(self):
        table = Table(expand=True, leading=1)
        table.add_column('Decoded Token')

        header_text = Text(overflow='fold')
        header_text.append('Header\n', style=HEADER_COLOR)
        header_text.append(pretty_json_dumps_(self.header), style=HEADER_COLOR)
        table.add_row(header_text)

        payload_text = Text(overflow='fold')
        payload_text.append('Payload\n', style=PAYLOAD_COLOR)
        payload_text.append(pretty_json_dumps_(self.payload), style=PAYLOAD_COLOR)
        table.add_row(payload_text)

        if self.verified is True:
            signature_text = Text(
                Emoji.replace('Signature Verified :blue_heart:'),
                style=SIGANTURE_VALID_COLOR
            )

        elif self.verified is False:
            signature_text = Text(
                Emoji.replace('Invalid Signature :skull:'),
                style=SIGNATURE_INVALID_COLOR
            )

        else:
            signature_text = Text(
                Emoji.replace('Skipped Signature Verification :eyes:'),
                style=SIGNATURE_SKIP_COLOR
            )

        table.add_row(signature_text)

        return table


@dataclass
class JSONDecodedToken:
    header :Dict
    payload :Dict

    def __rich_console__(self, *args, **kwargs) -> RenderResult:
        yield pretty_json_dumps_(
            {
                'header': self.header,
                'payload': self.payload,
            }
        )
