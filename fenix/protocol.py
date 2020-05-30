#
# Fenix protocol messages
#
# © Copyright 2020 by luk3yx and piesquared
#

# Optional __future__ import for testing
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from fenix import _protocolCore

import datetime
import json

class BaseProtocol(_protocolCore.BaseMessage):
    def dumps(self) -> str:
        return json.dumps(self._raw)

serverMessages: _protocolCore.ProtocolHelper = _protocolCore.ProtocolHelper()

@serverMessages.add('authUser')
class AuthUser(BaseProtocol):
    username: str
    email: str
    settings: Dict[str, Any]
    token: str
    usernameHash: int
    createdAt: datetime.datetime
    verified: bool
    servers: Dict[str, Dict[str, str]]

@serverMessages.add('reactionAdded')
class ReactionAdded(BaseProtocol):
    messageID: int
    numberOfReactions: int
    emoji: str

@serverMessages.add('messageSent')
class MessageSent(BaseProtocol):
    avatar: str
    nick: str
    messageID: int
    content: str
    timestamp: int
    channelID: int

@serverMessages.add('messageEdited')
class MessageEdited(BaseProtocol):
    messageID: int
    content: str

@serverMessages.add('messageDeleted')
class MessageDeleted(BaseProtocol):
    messageID: int

@serverMessages.add('channelInfo')
class ChannelInfo(BaseProtocol):
    """
    History is a List of a messages.  Keys would be
    ```
    {
      'messageID': int,
      'userID': int,
      'content': str,
      'timestamp': int
      'avatar': str
      'nick': str
    }
    ```
    """

    channelID: int
    history: List[Dict[str, Any]]
    channelName: str

@serverMessages.add('serverInfo')
class ServerInfo(BaseProtocol):
    """
    channels is a list of channels. Keys would be
    ```
    {
        'channelID': int
        'channelName': str
        'categoryName': str
    }
    ```

    users is a list of 20 users
    ```
    {
        'userID': int
        'roleID': int
        'avatar': str
        'nick': str
    }
    """
    serverID: int
    channels: List[Dict[str, Any]]
    users: List[Dict[str, Any]]
    serverAvatar: str
    serverName: str

@serverMessages.add('serverInfo')
class ChannelError(BaseProtocol):
    """
    Raised when a user doesn't have permission to view a channel,
    or a channel that doesnt exist is queried.
    """

@serverMessages.add('messageError')
class MessageError(BaseProtocol):
    """
    Raised when a user tries to delete or edit a nonexistant message.
    """

@serverMessages.add('BadFormat')
class BadFormat(BaseProtocol):
    """
    Raised when a user tries to send a message without the type field, without all the fields for the type, or with a nonexistant type.
    """

clientMessages: _protocolCore.ProtocolHelper = _protocolCore.ProtocolHelper()

@clientMessages.add('changeSubscribedChannel')
class ChangeSubscribedChannel(BaseProtocol):
    channelID: int

@clientMessages.add('createChannel')
class CreateChannel(BaseProtocol):
    serverID: int
    name: str

@clientMessages.add('sendMessage')
class SendMessage(BaseProtocol):
    channelID: int
    contents: str

@clientMessages.add('editMessage')
class EditMessage(BaseProtocol):
    messageID: int
    contents: str

@clientMessages.add('deleteMessage')
class DeleteMessage(BaseProtocol):
    messageID: int

@clientMessages.add('addReaction')
class AddReaction(BaseProtocol):
    messageID: int
    reaction: str

@clientMessages.add('removeReaction')
class RemoveReaction(BaseProtocol):
    messageID: int
    reaction: int

@clientMessages.add('changeServerPermission')
class ChangeServerPermission(BaseProtocol):
    permission: str
    value: bool
    serverID: int
    actor: int

@clientMessages.add('changeChannelPermission')
class ChangeChannelPermission(BaseProtocol):
    permission: str
    value: bool
    channelID: int
    actor: int

@clientMessages.add('getPerms')
class GetPerms(BaseProtocol):
    serverID: int

@clientMessages.add('getPermsList')
class GetPermsList(BaseProtocol):
    serverID: int

@clientMessages.add('hasChannelPermission')
class HasChannelPermission(BaseProtocol):
    permission: str
    channelID: int

@clientMessages.add('hasServerPermission')
class HasServerPermission(BaseProtocol):
    permission: str
    channelID: int

@clientMessages.add('getRoles')
class GetRoles(BaseProtocol):
    serverID: int

@clientMessages.add('getRolesList')
class GetRolesList(BaseProtocol):
    serverID: int

@clientMessages.add('joinRoles')
class JoinRoles(BaseProtocol):
    serverID: int
    roleID: int
    actor: int

@clientMessages.add('createServer')
class CreateServer(BaseProtocol):
    name: str

@clientMessages.add('getServer')
class GetServer(BaseProtocol):
    serverID: int

@clientMessages.add('getServers')
class GetUsersServers(BaseProtocol):
    serverID: int

@clientMessages.add('getServersList')
class GetServersList(BaseProtocol):
    serverID: int