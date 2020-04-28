#
# Fenix protocol messages
#
# © Copyright 2020 by luk3yx and piesquared
#

# Optional __future__ import for testing
from __future__ import annotations

from typing import Dict, Union, Any

from fenix import _protocolCore

import datetime

class BaseProtocol(_protocolCore.BaseMessage):
	pass

outgoingMessages: _protocolCore.ProtocolHelper = _protocolCore.ProtocolHelper()
@outgoingMessages.add('authUser')
class AuthUser(BaseProtocol):
	id: int
	username: str
	email: str
	settings: Dict[str, Any]
	token: str
	usernameHash: int
	createdAt: datetime.datetime
	verified: bool
	servers: Dict[str, Dict[str, str]]

incomingMessages: _protocolCore.ProtocolHelper = _protocolCore.ProtocolHelper()

@incomingMessages.add('signIn')
class SignIn(BaseProtocol):
	email: str
	password: str

@incomingMessages.add('signUp')
class SignUp(BaseProtocol):
	email: str
	username: str
	password: str

@incomingMessages.add('createChannel')
class CreateChannel(BaseProtocol):
	serverID: int
	name: str

@incomingMessages.add('sendMessage')
class SendMessage(BaseProtocol):
	channelID: int
	contents: str

@incomingMessages.add('editMessage')
class EditMessage(BaseProtocol):
	messageID: int
	contents: str

@incomingMessages.add('deleteMessage')
class DeleteMessage(BaseProtocol):
	messageID: int

@incomingMessages.add('addReaction')
class AddReaction(BaseProtocol):
	messageID: int
	reaction: str

@incomingMessages.add('removeReaction')
class RemoveReaction(BaseProtocol):
	messageID: int
	reaction: int

@incomingMessages.add('changeServerPermission')
class ChangeServerPermission(BaseProtocol):
	permission: str
	value: bool
	userID: int
	serverID: int
	actor: int

@incomingMessages.add('changeChannelPermission')
class ChangeChannelPermission(BaseProtocol):
	permission: str
	value: bool
	userID: int
	channelID: int
	actor: int

@incomingMessages.add('getPerms')
class GetPerms(BaseProtocol):
	userID: int
	serverID: int

@incomingMessages.add('getPermsList')
class GetPermsList(BaseProtocol):
	userID: int
	serverID: int

@incomingMessages.add('hasChannelPermission')
class HasChannelPermission(BaseProtocol):
	permission: str
	userID: int
	channelID: int

@incomingMessages.add('hasServerPermission')
class HasServerPermission(BaseProtocol):
	permission: str
	userID: int
	channelID: int

@incomingMessages.add('getRoles')
class GetRoles(BaseProtocol):
	userID: int
	serverID: int

@incomingMessages.add('getRolesList')
class GetRolesList(BaseProtocol):
	userID: int
	serverID: int

@incomingMessages.add('joinRoles')
class JoinRoles(BaseProtocol):
	userID: int
	serverID: int
	roleID: int
	actor: int

@incomingMessages.add('createServer')
class CreateServer(BaseProtocol):
	userID: int
	name: str

@incomingMessages.add('getServer')
class GetServer(BaseProtocol):
	serverID: int

@incomingMessages.add('getServers')
class GetServers(BaseProtocol):
	serverID: int

@incomingMessages.add('getServersList')
class GetServersList(BaseProtocol):
	serverID: int