#!/usr/bin/env python3
#
# Protocol message helpers
#
# Copyright © 2020 by piesquared and luk3yx
#

import base64
import datetime
import hashlib
import secrets
from typing import Any, Dict, List, Tuple, Iterator

try:
    import fenix.conf as conf
    password = conf.databasePassword
except ImportError:
    password = 'test'

import asyncpg
from email_validator import EmailNotValidError, validate_email

class Dataclass:

    def __iter__(self) -> Iterator[Any]:
        yield from self.__annotations__

    @classmethod
    def fromDict(cls, source: Dict[str, Any]): #type: ignore
        self = cls()
        for method in self:
            setattr(self, method, source[method])
        return self
    
class User(Dataclass):

    id: int
    username: str
    password: bytes
    email: str
    salt: bytes
    settings: Dict[str, Any]
    token: str
    usernameHash: str
    createdAt: datetime.datetime
    verified: bool
    servers: Dict[str, 'Server']

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'User':
        return super().fromDict(source) #type: ignore

class AuthUtils:
    @classmethod
    def checkPassword(cls, password: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha512', password, salt, 100000)


class Server(Dataclass):

    ID: int
    name: str
    createdAt: datetime.datetime
    settings: Dict[str, Any]

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Server':
        return super().fromDict(source) #type: ignore

    @classmethod
    def fromListToList(cls, source: List[Dict[str, Any]]) -> List['Server']:
        servers: List['Server'] = []
        for raw in source:
            servers.append(cls.fromDict(raw))

        return servers

    @classmethod
    def fromListToDict(cls, source: List[Dict[str, Any]]) -> Dict[int, 'Server']:
        servers: Dict[int, 'Server'] = {}
        for raw in source:
            server = cls.fromDict(raw)
            servers[server.ID] = server

        return servers
        
class Role(Dataclass):
    name: str
    color: str
    id: int

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Role':
        return super().fromDict(source) #type: ignore

    @classmethod
    def fromListToDict(cls, source: List[Dict[str, Any]]) -> Dict[int, 'Role']:
        roles: Dict[int, 'Role'] = {}
        for raw in source:
            role = cls.fromDict(raw)
            roles[role.id] = role

        return roles

    @classmethod
    def fromListToList(cls, source: List[Dict[str, Any]]) -> List['Role']:
        roles: List['Role'] = []
        for raw in source:
            roles.append(cls.fromDict(raw))

        return roles

serverRegistrationWhiteList: Tuple[str, ...] = ('admin', 'addChannels', 'assignRoles', 'kick', 'ban', 'changeNick', 'changeOthersNick')

class ServerRegistration(Dataclass):
    userID: int
    serverID: int
    roles: List[int]
    admin: bool
    addChannels: bool
    assignRoles: bool
    kick: bool
    ban: bool
    changeNick: bool
    changeOthersNick: bool
    
    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'ServerRegistration':
        return super().fromDict(source) #type: ignore

    @classmethod
    def fromListToList(cls, source: List[Dict[str, Any]]) -> List['ServerRegistration']:
        serverRegistration: List['ServerRegistration'] = []
        for raw in source:
            serverRegistration.append(cls.fromDict(raw))

        return serverRegistration
channelPermissionsWhiteList: Tuple[str, ...] = ('canRead', 'canTalk', 'canReadHistory', 'canDeleteMessages', 'canManageChannel', 'canPinMessages', 'canMentionEveryone')

class ChannelPermissions(Dataclass):
    userID: int
    channelID: int
    canRead: bool
    canTalk: bool
    canReadHistory: bool
    canDeleteMessages: bool
    canManageChannel: bool
    canManagePermissions: bool
    canPinMessages: bool
    canMentionEveryone: bool
    canAddReactions: bool
    
    
    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'ChannelPermissions':
        return super().fromDict(source) #type: ignore

class Message(Dataclass):
    userID: int
    channelID: int
    content: str
    timestamp: datetime.datetime
    pinned: bool
    reactions: List[int]
    
    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Message':
        return super().fromDict(source) #type: ignore

class Reaction(Dataclass):
    id: int
    unicode: str
    users: List[int]

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Reaction':
        return super().fromDict(source) #type: ignore
        
class Channel(Dataclass):
    id: int
    name: str
    serverID: int
    createdAt: datetime.datetime
    
    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Channel':
        return super().fromDict(source) #type: ignore


class _Database:

    def __init__(self, databaseUrl: str = 'postgresql://piesquared@localhost:5432/fenix') -> None:
        self.__databaseUrl: str = databaseUrl

    __pool: asyncpg.Connection = None

    async def __connect(self) -> None:
        self.__pool: asyncpg.Connection = await asyncpg.create_pool(self.__databaseUrl, password=password)

    async def _execute(self, statement: str, *bindings: Any) -> None:
        if self.__pool is None:
            await self.__connect()

        await self.__pool.execute(statement, *bindings) #type: ignore

    async def _fetch(self, statement: str, *bindings: Any) -> asyncpg.Record:
        if self.__pool is None:
            await self.__connect()

        return await self.__pool.fetch(statement, *bindings) #type: ignore

class _SQL:
    fetchUserByEmail = 'SELECT * FROM Users WHERE email = $1'
    signUp = 'INSERT INTO Users(username, password, email, salt, token, createdAt, verified) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, TRUE) RETURNING *'
    getServers = 'SELECT * FROM ServerRegistration INNER JOIN Servers ON ServerRegistration.userID = CAST($1 AS INT) and Servers.id = ServerRegistration.serverID'
    signIn = 'SELECT * FROM Users WHERE email = $1 and password = $2'
    getPerms = 'SELECT * FROM ServerRegistration WHERE userID = CAST($1 AS INT) and serverID = CAST($2 AS INT)'
    getRoles = 'SELECT ServerRegistration.Roles FROM ServerRegistration INNER JOIN Roles ON ServerRegistration.userID = CAST($1 AS INT) AND ServerRegistration.serverID = CAST($2 AS INT) AND Roles.id = ANY(ServerRegistration.roles)'
    joinServer = 'INSERT INTO ServerRegistration(userID, serverID) VALUES ($1, $2)'
    getServer = 'SELECT * FROM Servers WHERE id = $1'
    joinRole = 'UPDATE ServerRegistration SET Roles = array_append(Roles, $1) WHERE userID = $2 AND serverID = $3 and (SELECT assignRoles FROM ServerRegistration WHERE serverID = $3 and userID = $4) = TRUE'
    createRole = 'CASE WHEN (SELECT assignRoles FROM ServerRegistration WHERE serverID = $3 and userID = $4) = TRUE THEN INSERT INTO Roles (serverID, name, color) VALUES ($1, $2, $3)'
    getRole = 'SELECT * FROM Roles WHERE id = $1'
    createServer = 'INSERT INTO Servers (ownerID, createdAt, name) VALUES (CAST($1 AS INT), CURRENT_TIMESTAMP, $2) RETURNING id'
    changeChannelPermission = 'UPDATE ChannelPermissions SET $1 = $2 WHERE userID = $3 and channelID = $4 AND (SELECT canManageServer FROM ChannelPermissions WHERE channelID = $4 and userID = $5) RETURNING *'
    changeServerPermission = 'UPDATE ServerRegistration SET $1 = $2 WHERE userID = $3 and serverID = $4 AND (SELECT canManageServer FROM ServerRegistration WHERE serverID = $4 and userID = $5) RETURNING *'
    hasChannelPermission = 'SELECT $1 FROM ChannelPermissions WHERE userID = $2 and channelID = $3'
    hasServerPermission = 'SELECT $1 FROM ServerRegistration WHERE userID = $2 and serverID = $3'
    sendMessage = 'CASE WHEN (SELECT canTalk from ChannelPermissions WHERE channelID = $1 AND userID = $2) THEN INSERT INTO Messages (channelID, userID, contents, stamp) VALUES ($1, $2, $3, CURRENT_TIMESTAMP) RETURNING * '
    editMessage = 'CASE WHEN (SELECT canTalk from ChannelPermissions WHERE channelID = $4 AND userID = $3) THEN UPDATE Messages SET contents = $1 WHERE id = $2 and userID = $3 RETURNING *'
    deleteMessage = 'DELETE Messages WHERE id = $1 AND userID = $2'
    # 1: messageID, 2 userID 3 channelID 4 unicode
    addReaction = '''CASE WHEN (SELECT canAddReactions from ChannelPermissions WHERE channelID = $3 AND userID = $2) AND 
                    (SELECT canTalk from ChannelPermissions WHERE channelID = $3 AND userID = $2) THEN CASE WHEN (ARRAY_LENGTH(
                    (SELECT reactions FROM Messages WHERE messageID = $1)) = 0) THEN UPDATE Messages SET reactions ARRAY_APPEND(
                    reactions, (INSERT INTO Reactions(unicode, messageID, users) 
                    VALUES ($4, $1, {$2}) RETURNING id)) WHERE id = $1 AND userID = $2 RETURN * ELSE UPDATE Messages SET reactions
                    ARRAY_APPEND(reactions, (SELECT id FROM Reactions WHERE messageID = $1) WHERE id = $1 AND userID = $2 RETURN *'''
                    
    pinMessage = 'CASE WHEN (SELECT canTalk from ChannelPermissions WHERE channelID = $1 AND userID = $2) THEN UPDATE Messages SET pinned = $1 WHERE id = $2 AND userID = $3 RETURN *'
    removeReaction1 = '''UPDATE Messages SET ARRAY_REMOVE(reactions, $1) WHERE id = (SELECT messageID FROM Reactions WHERE id = $1)'''
    removeReaction2 = '''DELETE Reactions WHERE id = $1'''
    createChannel = 'INSERT INTO Channels(name, serverID, createdAt) VALUES ($1, $2, CURRENT_TIMESTAMP) RETURN *'
class Database(_Database):

    async def fetchUserByEmail(self, email: str) -> User:
        query = await self._fetch(_SQL.fetchUserByEmail, email)
        try:
            return User.fromDict(query[0])
        except (IndexError, KeyError):
            raise UserNotFound(f'{email} is not registered!')

    async def __validate(self, username: str, password: bytes, email: str) -> None:
        # Check if the user is already registered
        try:
            await self.fetchUserByEmail(email)
            raise InvalidCredentials
        except UserNotFound:
            pass

        # Check if the username is above 3 characters and below 32
        if not len(username) >= 3 or not len(username) <= 32:
            raise InvalidCredentials

        # Validate the email
        try:
            validate_email(email)
        except EmailNotValidError:
            raise InvalidCredentials from None

    async def signUp(self, username: str, password: str, email: str) -> User:
        await self.__validate(username, password.encode('utf-8'), email)

        salt = secrets.token_hex(32).encode('utf-8')
        token = secrets.token_hex(128)
        hash: bytes = AuthUtils.checkPassword(password.encode('utf-8'), salt)

        user = await self._fetch(_SQL.signUp, username, hash, email, salt, token)

        return User.fromDict(user[0])

    async def signIn(self, email: str, password: str) -> User:
        user: User = await self.fetchUserByEmail(email)

        hash: bytes = AuthUtils.checkPassword(password.encode('utf-8'), user.salt)

        if not secrets.compare_digest(hash, user.password):
            raise InvalidCredentials

        return user

    async def getServers(self, id: int) -> Dict[int, Server]:
        servers = await self._fetch(_SQL.getServers, id)

        try:
            return Server.fromListToDict(servers)

        except KeyError:
            return {}

    async def getPerms(self, userID: int, serverID: int) -> ServerRegistration:
        perms = await self._fetch(_SQL.getPerms, userID, serverID)
        return ServerRegistration.fromDict(perms)

    async def getRoles(self, userID: int, serverID: int) -> Dict[int, Role]:
        roles = await self._fetch(_SQL.getRoles, userID, serverID)

        try:
            return Role.fromListToDict(roles)

        except KeyError:
            return {}

    async def getServersList(self, id: int) -> List[Server]:
        servers = await self._fetch(_SQL.getServers, id)

        try:
            return Server.fromListToList(servers)

        except KeyError:
            return []

    async def getPermsList(self, userID: int, serverID: int) -> List[ServerRegistration]:
        perms = await self._fetch(_SQL.getPerms, userID, serverID)
        return ServerRegistration.fromListToList(perms)

    async def getRolesList(self, userID: int, serverID: int) -> List[Role]:
        roles = await self._fetch(_SQL.getRoles, userID, serverID)

        try:
            return Role.fromListToList(roles)

        except KeyError:
            return []

    async def joinServer(self, userID: int, serverID: int) -> Server:
        await self._execute(_SQL.joinServer, userID, serverID)
        server = await self._fetch(_SQL.getServer, int(serverID))

        return Server.fromDict(server[0])

    async def joinRole(self, userID: int, serverID: int, roleID: int, actor: int) -> Role:
        await self._execute(_SQL.joinRole, roleID, userID, serverID)
        role = await self._fetch(_SQL.getRole, roleID)
        return Role.fromDict(role)
    
    def validate(self, name: str) -> None:
        if len(name) > 40:
            raise InvalidServerName

    async def getServer(self, serverID: int) -> Server:
        server = await self._fetch(_SQL.getServer, serverID)
        return Server.fromDict(server[0])

    async def createServer(self, userID: int, name: str) -> Server:
        self.validate(name)

        serverID = await self._fetch(_SQL.createServer, int(userID), name)
        server = await self.getServer(serverID[0]['id'])

        return server
    
    async def hasChannelPermission(self, permission: str, userID: int, channelID: int) -> bool:
        if permission not in channelPermissionsWhiteList:
            raise InvalidPermissionName
        
        permissions = await self._fetch(_SQL.hasChannelPermission, permission, userID, channelID)
        
        return bool(permissions[0])

    async def hasServerPermission(self, permission: str, userID: int, serverID: int) -> bool:
        if permission not in serverRegistrationWhiteList:
            raise InvalidPermissionName
        
        permissions = await self._fetch(_SQL.hasServerPermission, permission, userID, serverID)
        
        return bool(permissions[0])
    
    async def changechannelPermission(self, permission: str, value: bool, userID: int, channelID: int, actor: int) -> ChannelPermissions:
        if permission not in channelPermissionsWhiteList:
            raise InvalidPermissionName
        
        permissions = await self._fetch(_SQL.changeChannelPermission, permission, value, userID, channelID, actor)
        
        if permissions[0] is None:
            raise ActorNotAuthorized

        return ChannelPermissions.fromDict(permissions[0])
    
    async def changeServerPermission(self, permission: str, value: bool, userID: int, serverID: int, actor: int) -> ServerRegistration:
        if permission not in serverRegistrationWhiteList:
            raise InvalidPermissionName
        
        permissions = await self._fetch(_SQL.changeServerPermission, permission, value, userID, serverID, actor)
        
        if permissions[0] is None:
            raise ActorNotAuthorized

        return ServerRegistration.fromDict(permissions[0])
    
    async def sendMessage(self, content: str, userID: int, channelID: int) -> Message:
        if len(content) >= 1000:
            raise MessageTooLong
        message = await self._fetch(_SQL.sendMessage, channelID, userID, content)
        return Message.fromDict(message[0])
    
    async def editMessage(self, messageID: int, userID: int, content: str) -> Message:
        if len(content) >= 1000:
            raise MessageTooLong
        
        message = await self._fetch(_SQL.editMessage, content, messageID, userID)
        return Message.fromDict(message[0])
    
    async def deleteMessage(self, messageID: int, userID: int) -> None:
        await self._execute(_SQL.deleteMessage, messageID, userID)
    
    async def addReaction(self, messageID: int, userID: int, channelID: int, unicode: str) -> Message:
        message = await self._fetch(_SQL.addReaction, messageID, userID, channelID, unicode)
        
        return Message.fromDict(message[0])
    
    async def removeReaction(self, reactionID: int) -> None:
        await self._execute(_SQL.removeReaction1, reactionID)
        await self._execute(_SQL.removeReaction2, reactionID)
    
    async def createChannel(self, serverID: int, name: str) -> Channel:
        channel = await self._fetch(_SQL.createChannel, name, serverID)
        return Channel.fromDict(channel)
        
class CannotTalk(Exception):
    pass

class MessageTooLong(Exception):
    pass

class InvalidServerName(Exception):
    pass

class ActorNotAuthorized(Exception):
    pass

class InvalidPermissionName(Exception):
    pass

class UserNotFound(Exception):
    pass

class InvalidCredentials(Exception):
    pass
