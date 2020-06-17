#
# Fenix protocol messages
#
# © Copyright 2020 by luk3yx and piesquared
#

# Optional __future__ import for testing
from __future__ import annotations

import datetime
import json
from typing import Any, Dict, List, Optional, Union

from fenix import _protocolCore


serverMessages: _protocolCore.ProtocolHelper = _protocolCore.ProtocolHelper()

@serverMessages.add('AuthUser')
class AuthUser(_protocolCore.BaseMessage):
    username: str
    email: str
    settings: Optional[Dict[str, Any]]
    token: str
    usernameHash: int
    createdAt: int
    verified: bool
    servers: List[Dict[str, Any]]

@serverMessages.add('ReactionAdded')
class ReactionAdded(_protocolCore.BaseMessage):
    messageID: int
    numberOfReactions: int
    emoji: str

@serverMessages.add('MessageSent')
class MessageSent(_protocolCore.BaseMessage):
    avatar: str
    nick: str
    messageID: int
    content: str
    timestamp: int
    channelID: int

@serverMessages.add('MessageEdited')
class MessageEdited(_protocolCore.BaseMessage):
    messageID: int
    content: str

@serverMessages.add('MessageDeleted')
class MessageDeleted(_protocolCore.BaseMessage):
    messageID: int

@serverMessages.add('ChannelInfo')
class ChannelInfo(_protocolCore.BaseMessage):
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

@serverMessages.add('ServerInfo')
class ServerInfo(_protocolCore.BaseMessage):
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

@serverMessages.add('ServerInfo')
class ChannelError(_protocolCore.BaseMessage):
    """
    Raised when a user doesn't have permission to view a channel,
    or a channel that doesnt exist is queried.
    """

@serverMessages.add('MessageError')
class MessageError(_protocolCore.BaseMessage):
    """
    Raised when a user tries to delete or edit a nonexistant message, or its too long.
    """

@serverMessages.add('BadFormat')
class BadFormat(_protocolCore.BaseMessage):
    """
    Raised when a user tries to send a message without the type field, without all the fields for the type, or with a nonexistant type.
    """



@serverMessages.add('ActorNotAuthorized')
class ActorNotAuthorized(_protocolCore.BaseMessage):
    pass

@serverMessages.add('SentMessage')
class SentMessage(_protocolCore.BaseMessage):
    channelID: int
    userID: int
    content: str
    timestamp: str
    pinned: bool
    messageID: int

clientMessages: _protocolCore.ProtocolHelper = _protocolCore.ProtocolHelper()

@clientMessages.add('ChangeSubscribedChannel')
class ChangeSubscribedChannel(_protocolCore.BaseMessage):
    channelID: int

@clientMessages.add('CreateChannel')
class CreateChannel(_protocolCore.BaseMessage):
    serverID: int
    name: str

@clientMessages.add('SendMessage')
class SendMessage(_protocolCore.BaseMessage):
    channelID: int
    contents: str

@clientMessages.add('EditMessage')
class EditMessage(_protocolCore.BaseMessage):
    messageID: int
    contents: str

@clientMessages.add('DeleteMessage')
class DeleteMessage(_protocolCore.BaseMessage):
    messageID: int

@clientMessages.add('AddReaction')
class AddReaction(_protocolCore.BaseMessage):
    messageID: int
    reaction: str

@clientMessages.add('RemoveReaction')
class RemoveReaction(_protocolCore.BaseMessage):
    messageID: int
    reaction: int

@clientMessages.add('ChangeServerPermission')
class ChangeServerPermission(_protocolCore.BaseMessage):
    permission: str
    value: bool
    serverID: int
    actor: int

@clientMessages.add('ChangeChannelPermission')
class ChangeChannelPermission(_protocolCore.BaseMessage):
    permission: str
    value: bool
    channelID: int
    actor: int

@clientMessages.add('GetPerms')
class GetPerms(_protocolCore.BaseMessage):
    serverID: int

@clientMessages.add('GetPermsList')
class GetPermsList(_protocolCore.BaseMessage):
    serverID: int

@clientMessages.add('HasChannelPermission')
class HasChannelPermission(_protocolCore.BaseMessage):
    permission: str
    channelID: int

@clientMessages.add('HasServerPermission')
class HasServerPermission(_protocolCore.BaseMessage):
    permission: str
    channelID: int

@clientMessages.add('GetRoles')
class GetRoles(_protocolCore.BaseMessage):
    serverID: int

@clientMessages.add('GetRolesList')
class GetRolesList(_protocolCore.BaseMessage):
    serverID: int

@clientMessages.add('JoinRoles')
class JoinRoles(_protocolCore.BaseMessage):
    serverID: int
    roleID: int
    actor: int

@clientMessages.add('CreateServer')
class CreateServer(_protocolCore.BaseMessage):
    name: str

@clientMessages.add('GetServer')
class GetServer(_protocolCore.BaseMessage):
    serverID: int

@clientMessages.add('GetServers')
class GetUsersServers(_protocolCore.BaseMessage):
    serverID: int

@clientMessages.add('GetServersList')
class GetServersList(_protocolCore.BaseMessage):
    serverID: int
