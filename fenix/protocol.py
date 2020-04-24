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

incomingMessages: _protocolCore.ProtocolHelper = _protocolCore.ProtocolHelper()

@incomingMessages.add('signIn')
class SignIn(_BaseProtocol):
    email: str
    password: str

@incomingMessages.add('signUp')
class SignUp(_BaseProtocol):
    email: str
    username: str
    password: str

@incomingMessages.add('createChannel')
class CreateChannel(_BaseProtocol):
    serverID: int
    name: str
    
@incomingMessages.add('sendMessage')
class SendMessage(_BaseProtocol):
    channelID: int
    contents: str
    
@incomingMessages.add('editMessage')
class EditMessage(_BaseProtocol):
    messageID: int
    contents: str

@incomingMessages.add('deleteMessage')
class DeleteMessage(_BaseProtocol):
    messageID: int
    
@incomingMessages.add('addReaction')
class AddReaction(_BaseProtocol):
    messageID: int
    reaction: str

@incomingMessages.add('removeReaction')
class RemoveReaction(_BaseProtocol):
    messageID: int
    reaction: int
    
@incomingMessages.add('changeServerPermission')
class ChangeServerPermission(_BaseProtocol):
    permission: str
    value: bool
    userID: int
    serverID: int
    actor: int
    
@incomingMessages.add('changechannelPermission')
class ChangechannelPermission(_BaseProtocol):
    permission: str
    value: bool
    userID: int
    channelID: int
    actor: int

@incomingMessages.add('getPerms')
class GetPerms(_BaseProtocol):
    userID: int
    serverID: int

@incomingMessages.add('getPermsList')
class GetPermsList(_BaseProtocol):
    userID: int
    serverID: int
    
@incomingMessages.add('hasChannelPermission')
class HasChannelPermission(_BaseProtocol):
    permission: str
    userID: int
    channelID: int

@incomingMessages.add('hasServerPermission')
class HasServerPermission(_BaseProtocol):
    permission: str
    userID: int
    channelID: int

@incomingMessages.add('getRoles')
class GetRoles(_BaseProtocol):
    userID: int
    serverID: int

@incomingMessages.add('getRolesList')
class GetRolesList(_BaseProtocol):
    userID: int
    serverID: int

@incomingMessages.add('joinRoles')
class JoinRoles(_BaseProtocol):
    userID: int
    serverID: int
    roleID: int
    actor: int
    
@incomingMessages.add('createServer')
class CreateServer(_BaseProtocol):
    userID: int
    name: str

@incomingMessages.add('getServer')
class GetServer(_BaseProtocol):
    serverID: int

@incomingMessages.add('getServers')
class GetServers(_BaseProtocol):
    serverID: int

@incomingMessages.add('getServersList')
class GetServersList(_BaseProtocol):
    serverID: int

@incomingMessages.add('joinServer')
class GetServer(_BaseProtocol):
    serverID: int
    userID: int