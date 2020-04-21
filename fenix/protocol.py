# Example code

# Optional __future__ import for testing
from __future__ import annotations

from fenix import _protocol_core
from typing import Dict, Union


class BaseProtocol(_protocol_core.BaseMessage):
    async def process(self) -> None:
        pass

class Hello(BaseProtocol):
    username: str
    id: Union[str, int]
    ignores: Dict[str, bool]

def test() -> None:
    Hello({'username': 'test', 'id': 123, 'ignores': {'incorrect': 'type'}})
