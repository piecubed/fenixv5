#
# Fenix protocol messages
#
# © Copyright 2020 by luk3yx and piesquared
#

# Optional __future__ import for testing
from __future__ import annotations

from fenix import _protocol_core
from typing import Dict, Type, Union


class BaseProtocol(_protocol_core.BaseMessage):
    async def process(self) -> None:
        pass

_incoming_messages = _protocol_core.ProtocolHelper()

@_incoming_messages.add('captcha')
class _Captcha(BaseProtocol):
    link: str # Original link to captcha
    text: str # Completed text

@_incoming_messages.add('channelCreate')
class _ChannelCreate(BaseProtocol):
    channel: str
    server: int

@_incoming_messages.add('login')
class _Login(BaseProtocol):
    email: str
    password: str

@_incoming_messages.add('loginBot')
class _LoginBot(BaseProtocol):
    token: str

@_incoming_messages.add('message')
class _Message(BaseProtocol):
    channel_id: int
    message: str

@_incoming_messages.add('register')
class _Register(BaseProtocol):
    email: str
    username: str
    password: str

@_incoming_messages.add('registerBot')
class _RegisterBot(BaseProtocol):
    name: str
    parent_email: str
    parent_password: str

@_incoming_messages.add('verify')
class _Verify(BaseProtocol):
    code: str

@_incoming_messages.add('version')
class _Version(BaseProtocol):
    pass
