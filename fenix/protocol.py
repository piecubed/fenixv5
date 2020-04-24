#
# Fenix protocol messages
#
# © Copyright 2020 by luk3yx and piesquared
#

# Optional __future__ import for testing
from __future__ import annotations

from typing import Dict, Type, Union

from fenix import _protocolCore


class _BaseProtocol(_protocolCore.BaseMessage):
    async def process(self) -> None:
        pass

incomingMessages = _protocolCore.ProtocolHelper()


@incomingMessages.add('captcha')
class Captcha(_BaseProtocol):
    link: str # Original link to captcha
    text: str # Completed text

@incomingMessages.add('createChannel')
class CreateChannel(_BaseProtocol):
    channel: int
    server: int

@incomingMessages.add('fetchUserByID')
class FetchUserByID(_BaseProtocol):
    id: int

@incomingMessages.add('signIn')
class SignIn(_BaseProtocol):
    email: str
    password: str

@incomingMessages.add('getServers')
@incomingMessages.add('loginAsBot')
class LoginAsBot(_BaseProtocol):
    token: str

@incomingMessages.add('message')
class Message(_BaseProtocol):
    channelID: int
    message: str

@incomingMessages.add('signUp')
class SignUp(_BaseProtocol):
    email: str
    username: str
    password: str

@incomingMessages.add('registerBot')
class RegisterBot(_BaseProtocol):
    name: str
    parent_email: str
    parent_password: str

@incomingMessages.add('verify')
class Verify(_BaseProtocol):
    code: str

@incomingMessages.add('version')
class Version(_BaseProtocol):
    pass
