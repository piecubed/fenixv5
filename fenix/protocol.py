#
# Fenix protocol messages
#
# © Copyright 2020 by luk3yx and piesquared
#

# Optional __future__ import for testing
from __future__ import annotations

from typing import Dict, Type, Union

from fenix import _protocolCore


class BaseProtocol(_protocolCore.BaseMessage):
    async def process(self) -> None:
        pass

incomingMessages = _protocolCore.ProtocolHelper()

@incomingMessages.add('captcha')
class _Captcha(BaseProtocol):
    link: str # Original link to captcha
    text: str # Completed text

@incomingMessages.add('channelCreate')
class _ChannelCreate(BaseProtocol):
    channel: str
    server: int

@incomingMessages.add('login')
class _Login(BaseProtocol):
    email: str
    password: str

@incomingMessages.add('loginBot')
class _LoginBot(BaseProtocol):
    token: str

@incomingMessages.add('message')
class _Message(BaseProtocol):
    channel_id: int
    message: str

@incomingMessages.add('register')
class _Register(BaseProtocol):
    email: str
    username: str
    password: str

@incomingMessages.add('registerBot')
class _RegisterBot(BaseProtocol):
    name: str
    parent_email: str
    parent_password: str

@incomingMessages.add('verify')
class _Verify(BaseProtocol):
    code: str

@incomingMessages.add('version')
class _Version(BaseProtocol):
    pass
