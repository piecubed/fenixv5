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
class Captcha(BaseProtocol):
    link: str # Original link to captcha
    text: str # Completed text

@incomingMessages.add('createChannel')
class CreateChannel(BaseProtocol):
    channel: int
    server: int

@incomingMessages.add('fetchUserByID')
class FetchUserByID(BaseProtocol):
    id: int

@incomingMessages.add('signIn')
class SignIn(BaseProtocol):
    email: str
    password: str

@incomingMessages.add('getServers')
@incomingMessages.add('loginAsBot')
class LoginAsBot(BaseProtocol):
    token: str

@incomingMessages.add('message')
class Message(BaseProtocol):
    channelID: int
    message: str

@incomingMessages.add('signUp')
class SignUp(BaseProtocol):
    email: str
    username: str
    password: str

@incomingMessages.add('registerBot')
class RegisterBot(BaseProtocol):
    name: str
    parent_email: str
    parent_password: str

@incomingMessages.add('verify')
class Verify(BaseProtocol):
    code: str

@incomingMessages.add('version')
class Version(BaseProtocol):
    pass
