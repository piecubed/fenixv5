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
from enum import Enum
from typing import Any, Dict, Iterator, List, Tuple, Optional

import asyncpg
from email_validator import EmailNotValidError, validate_email
from emoji.unicode_codes import EMOJI_UNICODE
import uuid
import time

try:
    import fenix.conf as conf
    password = conf.databasePassword
except ImportError:
    password = None

class Dataclass:

    _slots: Tuple[str, ...]
    _raw: Dict[str, Any]

    def __iter__(self) -> Iterator[Any]:
        yield from self.__annotations__

    @classmethod
    def fromDict(cls, source: Dict[str, Any]):  #type: ignore
        self = cls()
        self._raw = source
        for i in range(len(self._slots)):
            setattr(self, self._slots[i], source[self._slots[i].lower()])
        return self


class User(Dataclass):
    _slots = ('userID', 'username', 'password', 'email', 'salt', 'settings',
              'token', 'usernameHash', 'createdAt', 'verified', 'servers')

    userID: uuid.UUID
    username: str
    password: bytes
    email: str
    salt: bytes
    settings: Dict[str, Any]
    token: str
    usernameHash: str
    createdAt: datetime.datetime
    verified: bool
    focusedChannel: uuid.UUID
    servers: Optional[List['Server']]

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'User':
        source = dict(source)
        if source.get('servers') is None:
            source['servers'] = []

        return super().fromDict(source)  #type: ignore


class AuthUtils:
    @classmethod
    def checkPassword(cls, password: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha512', password, salt, 100000)


class Server(Dataclass):
    _slots = ('serverID', 'name', 'createdAt')

    serverID: uuid.UUID
    name: str
    createdAt: datetime.datetime
    # icon: str

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Server':
        return super().fromDict(source)  #type: ignore

    @classmethod
    def fromListToList(cls, source: List[Dict[str, Any]]) -> List['Server']:
        servers: List['Server'] = []
        for raw in source:
            servers.append(cls.fromDict(raw))

        return servers

    @classmethod
    def fromListToDict(cls, source: List[Dict[str,
                                              Any]]) -> Dict[uuid.UUID, 'Server']:
        servers: Dict[uuid.UUID, 'Server'] = {}
        for raw in source:
            server = cls.fromDict(raw)
            servers[server.serverID] = server

        return servers


class Role(Dataclass):
    _slots = ('name', 'color', 'roleID')

    name: str
    color: str
    roleID: uuid.UUID

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Role':
        return super().fromDict(source)  #type: ignore

    @classmethod
    def fromListToDict(cls, source: List[Dict[str, Any]]) -> Dict[uuid.UUID, 'Role']:
        roles: Dict[uuid.UUID, 'Role'] = {}
        for raw in source:
            role: 'Role' = cls.fromDict(raw)
            roles[role.roleID] = role

        return roles

    @classmethod
    def fromListToList(cls, source: List[Dict[str, Any]]) -> List['Role']:
        roles: List['Role'] = []
        for raw in source:
            roles.append(cls.fromDict(raw))

        return roles

class ServerRegistration(Dataclass):

    _slots = ('userID', 'serverID', 'roles', 'admin', 'addChannels',
              'assignRoles', 'kick', 'ban', 'changeNick', 'changeOthersNick')
    userID: uuid.UUID
    serverID: uuid.UUID
    roles: List[uuid.UUID]
    admin: bool
    addChannels: bool
    assignRoles: bool
    kick: bool
    ban: bool
    changeNick: bool
    changeOthersNick: bool

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'ServerRegistration':
        return super().fromDict(source)  #type: ignore

    @classmethod
    def fromListToList(
            cls, source: List[Dict[str, Any]]) -> List['ServerRegistration']:
        serverRegistration: List['ServerRegistration'] = []
        for raw in source:
            serverRegistration.append(cls.fromDict(raw))

        return serverRegistration

class ServerPermissionsEnum(Enum):
    roles = 'roles'
    admin = 'admin'
    addChannels = 'addChannels'
    assignRoles = 'assignRoles'
    kick = 'kick'
    ban = 'ban'
    changeNick = 'changeNick'
    changeOthersNick = 'changeOthersNick'

class ChannelPermissions(Dataclass):

    _slots = ('userID', 'channelID', 'canRead', 'canTalk', 'canReadHistory',
              'canDeleteMessage', 'canManageChannel', 'canManagePermissions',
              'canPinMessages,'
              'canMenthonEveryone', 'canAddReactions')
    userID: uuid.UUID
    channelID: uuid.UUID
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
        return super().fromDict(source)  #type: ignore


class ChannelPermissionEnum(Enum):
    read = 'canRead'
    talk = 'canTalk'
    readHistory = 'canReadHistory'
    deleteMessages = 'canDeleteMessages'
    manageChannel = 'canManageChannel'
    managePermissions = 'canManagePermissions'
    pinMessages = 'canPinMessages'
    mentionEveryone = 'canMentionEveryone'
    addReactions = 'canAddReactions'


class Message(Dataclass):

    _slots = ('userID', 'channelID', 'content', 'timestamp', 'pinned',
              'messageID')
    userID: uuid.UUID
    channelID: uuid.UUID
    content: str
    timestamp: datetime.datetime
    pinned: bool
    reactions: List[uuid.UUID]
    messageID: uuid.UUID

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Message':
        return super().fromDict(source)  #type: ignore


class Reaction(Dataclass):
    reactionID: uuid.UUID
    unicode: str
    users: List[uuid.UUID]

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Reaction':
        return super().fromDict(source)  #type: ignore


class Channel(Dataclass):

    _slots = ('channelID', 'name', 'serverID', 'createdAt')
    channelID: uuid.UUID
    name: str
    serverID: uuid.UUID
    createdAt: datetime.datetime

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Channel':
        return super().fromDict(source)  #type: ignore


class ChannelHistory(Dataclass):

    _slots = ('channelID', 'name', 'serverID', 'createdAt')
    channelID: uuid.UUID
    name: str
    serverID: uuid.UUID
    createdAt: datetime.datetime
    messageHistory: List[Message]

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'ChannelHistory':
        return super().fromDict(source)  #type: ignore

class _Database:
    def __init__(
        self,
        databaseUrl: str = 'postgresql://piesquared@localhost:5432/fenix'
    ) -> None:
        self.__databaseUrl: str = databaseUrl

    __pool: asyncpg.Connection = None

    async def __connect(self) -> None:
        self.__pool: asyncpg.Connection = await asyncpg.create_pool(
            self.__databaseUrl, password='test')

    async def _execute(self, statement: str, *bindings: Any) -> None:
        if self.__pool is None:
            await self.__connect()

        await self.__pool.execute(statement, *bindings)  #type: ignore

    async def _fetch(self, statement: str, *bindings: Any) -> asyncpg.Record:
        if self.__pool is None:
            await self.__connect()

        return await self.__pool.fetch(statement, *bindings)  #type: ignore


class _SQL:
    fetchUserByEmail = 'SELECT * FROM Users WHERE email = $1'
    signUp = 'INSERT INTO Users(userID, username, password, email, salt, token, createdAt, verified) VALUES ($1, $2, $3, $4, $5, $6 CURRENT_TIMESTAMP, TRUE) RETURNING *'
    getServers = 'SELECT * FROM ServerRegistration INNER JOIN Servers ON ServerRegistration.userID = $1 and Servers.serverID = ServerRegistration.serverID'
    signIn = 'SELECT * FROM Users WHERE email = $1 and password = $2'
    getPerms = 'SELECT * FROM ServerRegistration WHERE userID = $1 and serverID = $2'
    getRoles = 'SELECT ServerRegistration.Roles FROM ServerRegistration INNER JOIN Roles ON ServerRegistration.userID = $1 AND ServerRegistration.serverID = $2 AND Roles.id = ANY(ServerRegistration.roles)'
    joinServer = 'SELECT joinServer($1, $2)'
    getServer = 'SELECT * FROM Servers WHERE serverID = $1'
    joinRole = 'UPDATE ServerRegistration SET Roles = array_append(Roles, $1) WHERE userID = $2 AND serverID = $3 and (SELECT assignRoles FROM ServerRegistration WHERE serverID = $3 and userID = $4) = TRUE'
    createRole = 'SELECT createRole($1, $2, $3, $4)'
    getRole = 'SELECT * FROM Roles WHERE roleID = $1'
    changeChannelPermission = 'UPDATE ChannelPermissions SET $1 = $2 WHERE userID = $3 and channelID = $4 AND (SELECT canManageServer FROM ChannelPermissions WHERE channelID = $4 and userID = $5) RETURNING *'
    changeServerPermission = 'UPDATE ServerRegistration SET $1 = $2 WHERE userID = $3 and serverID = $4 AND (SELECT canManageServer FROM ServerRegistration WHERE serverID = $4 and userID = $5) RETURNING *'
    hasChannelPermission = 'SELECT $1 FROM ChannelPermissions WHERE userID = $2 and channelID = $3'
    hasServerPermission = 'SELECT $1 FROM ServerRegistration WHERE userID = $2 and serverID = $3'
    sendMessage = 'SELECT sendMessage($1, $2, $3)'
    editMessage = 'SELECT editMessage($1, $2, $3, $4)'
    deleteMessage = 'SELECT deleteMessage($1)'
    addReaction = 'SELECT addReaction($1, $2, $3)'
    pinMessage = 'SELECT pinMessage($1, $2, $3, $4)'
    removeReaction1 = '''UPDATE Messages SET ARRAY_REMOVE(reactions, $1) WHERE messageID = (SELECT messageID FROM Reactions WHERE reactionID = $1)'''
    removeReaction2 = '''DELETE Reactions WHERE reactionID = $1'''
    createChannel = 'INSERT INTO Channels(name, serverID, createdAt) VALUES ($1, $2, CURRENT_TIMESTAMP) RETURNING *'
    fetchUserByToken = 'SELECT * FROM Users WHERE token = $1'


class Database(_Database):
    async def fetchUserByEmail(self, *, email: str) -> User:
        query = await self._fetch(_SQL.fetchUserByEmail, email)
        try:
            return User.fromDict(query[0])
        except (IndexError, KeyError):
            raise UserNotFound(f'{email} is not registered!')

    def makeID(self) -> uuid.UUID:
        return uuid.uuid4()

    async def __validate(self, *, username: str, password: str,
                         email: str) -> None:
        # Check if the user is already registered
        try:
            await self.fetchUserByEmail(email=email)
            raise InvalidCredentials
        except UserNotFound:
            pass

        # Check if the username is above 3 characters and below 32
        if not len(username) >= 3 or not len(username) <= 32:
            raise InvalidCredentials

        if len(password) < 9:
            raise InvalidCredentials

        # Validate the email
        try:
            validate_email(email)
        except EmailNotValidError:
            raise InvalidCredentials from None

    async def signUp(self, *, username: str, password: str,
                     email: str) -> User:
        await self.__validate(username=username,
                              password=password,
                              email=email)

        salt = secrets.token_hex(32).encode('utf-8')
        token = secrets.token_hex(128)
        hash: bytes = AuthUtils.checkPassword(password.encode('utf-8'), salt)
        userID = self.makeID()

        try:
            user = await self._fetch(_SQL.signUp, username, hash, email, salt,
                                     token)
        except asyncpg.UniqueViolationError:
            raise UserExists

        return User.fromDict(user[0])

    async def createSession(self,
                            channelID: uuid.UUID = uuid.UUID(int=0),
                            serverID: uuid.UUID = uuid.UUID(int=0),
                            *,
                            userID: uuid.UUID,
                            sessionID:  uuid.UUID) -> None:

        if channelID != uuid.UUID(int=0):
            if await self.hasChannelPermission(permission=ChannelPermissionEnum.read, userID=userID, channelID=channelID):
                return await self._execute(
                    'INSERT INTO FocusedItems(sessionID, channelID, serverID, userID) VALUES ($1, $2, $3, $4)',
                    sessionID, channelID, serverID, userID)
            raise ActorNotAuthorized()
        else:
            await self._execute(
                'INSERT INTO FocusedItems(sessionID, userID) VALUES($1, $2)', sessionID, userID
            )

    async def deleteSession(self, *, sessionID: uuid.UUID) -> None:
        await self._execute('DELETE FROM FocusedItems WHERE sessionID = $1',
                            sessionID)

    async def fetchUserByToken(self, *, token: str) -> User:
        user: List[asyncpg.Record] = await self._fetch('SELECT * FROM Users WHERE token = $1', token)

        if len(user) == 0:
            raise UserNotFound
        servers: List[asyncpg.Record] = await self._fetch('SELECT icon, name, Servers.serverID FROM Servers INNER JOIN ServerRegistration ON ServerRegistration.userID = $1 and ServerRegistration.serverID = Servers.serverID', user[0]['userid'])
        parsedServers = []

        for server in servers:
            parsedServers.append(dict(server))

        parsedUser = dict(user[0])

        parsedUser['servers'] = parsedServers
        return User.fromDict(parsedUser)

    async def tokenSignIn(self, *, token: str) -> User:
        user: User = await self.fetchUserByToken(token=token)

        if user.token != token:
            raise InvalidCredentials

        return user

    async def signIn(self, *, email: str, password: str) -> User:
        try:
            user: User = await self.fetchUserByEmail(email=email)
        except UserNotFound:
            raise InvalidCredentials

        hash: bytes = AuthUtils.checkPassword(password.encode('utf-8'),
                                              user.salt)

        if not secrets.compare_digest(hash, user.password):
            raise InvalidCredentials

        return user

    async def getServers(self, *, id: uuid.UUID) -> Dict[uuid.UUID, Server]:
        servers = await self._fetch(_SQL.getServers, id)

        try:
            return Server.fromListToDict(servers)

        except KeyError:
            return {}

    async def getPerms(self, *, userID: uuid.UUID,
                       serverID: uuid.UUID) -> ServerRegistration:
        perms = await self._fetch(_SQL.getPerms, userID, serverID)
        return ServerRegistration.fromDict(perms)

    async def getRoles(self, *, userID: uuid.UUID, serverID: uuid.UUID) -> Dict[uuid.UUID, Role]:
        roles = await self._fetch(_SQL.getRoles, userID, serverID)

        try:
            return Role.fromListToDict(roles)

        except KeyError:
            return {}

    async def getServersList(self, *, id: uuid.UUID) -> List[Server]:
        servers = await self._fetch(_SQL.getServers, id)

        try:
            return Server.fromListToList(servers)

        except KeyError:
            return []

    async def getPermsList(self, *, userID: uuid.UUID,
                           serverID: uuid.UUID) -> List[ServerRegistration]:
        perms = await self._fetch(_SQL.getPerms, userID, serverID)
        return ServerRegistration.fromListToList(perms)

    async def getRolesList(self, *, userID: uuid.UUID, serverID: uuid.UUID) -> List[Role]:
        roles = await self._fetch(_SQL.getRoles, userID, serverID)

        try:
            return Role.fromListToList(roles)

        except KeyError:
            return []

    async def joinServer(self, *, userID: uuid.UUID, serverID: uuid.UUID) -> Server:
        channels = await self._fetch('SELECT channelID FROM Channels WHERE serverID = $1', serverID)


        await self.__pool.executemany(f'INSERT INTO ChannelPermissions (userID, channelID) VALUES ({userID}, $1)', channels)

        return await self.getServer(serverID=serverID)

    async def joinRole(self, *, userID: uuid.UUID, serverID: uuid.UUID, roleID: uuid.UUID,
                       actor: uuid.UUID) -> Role:
        await self._execute(_SQL.joinRole, roleID, userID, serverID)
        role = await self._fetch(_SQL.getRole, roleID)
        return Role.fromDict(role)

    def validate(self, *, name: str) -> None:
        if len(name) > 40:
            raise InvalidServerName

    async def getServer(self, *, serverID: uuid.UUID) -> Server:
        server = await self._fetch(_SQL.getServer, serverID)
        return Server.fromDict(server[0])

    async def createServer(self, *, userID: uuid.UUID, name: str, sessionID: uuid.UUID) -> Server:
        self.validate(name=name)
        server = (await self._fetch('INSERT INTO Servers (ownerID, createdAt, name) VALUES ($1, CURRENT_TIMESTAMP, $2) RETURNING *', userID, name))[0]
        serverID = server['serverid']
        channelID = (await self._fetch('INSERT INTO Channels (name, serverID, createdAt) VALUES ($1, $2, CURRENT_TIMESTAMP) RETURNING channelID', 'General', serverID))[0][0]
        await self._execute('INSERT INTO ChannelPermissions (userID, channelID, canDeleteMessages, canManageChannel, canManagePermissions, canPinMessages) VALUES ($1, $2, TRUE, TRUE, TRUE, TRUE)', userID, channelID)
        await self._execute('INSERT INTO ServerRegistration (userID, serverID, admin, addChannels, assignRoles, kick, ban, changeOthersNick) VALUES ($1, $2, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE)', userID, serverID)
        await self.changeSubscribedChannel(channelID=channelID, userID=userID, sessionID=sessionID)
        await self.changeSubscribedServer(serverID=serverID, userID=userID, sessionID=sessionID)

        return Server.fromDict(server)

    async def hasChannelPermission(self, *, permission: ChannelPermissionEnum, userID: uuid.UUID,
                                   channelID: uuid.UUID) -> bool:

        permissions = await self._fetch(_SQL.hasChannelPermission, str(permission),
                                        userID, channelID)
        try:
            hasPermission = bool(permissions[0])
        except IndexError:
            hasPermission = False

        return hasPermission

    async def hasChannelPermissions(self, *, permissions: List[ChannelPermissionEnum], userID: uuid.UUID, channelID: uuid.UUID) -> bool:
        for permission in permissions:
            if not await self.hasChannelPermission(permission=permission, channelID=channelID, userID=userID):
                return False
        return True

    async def hasServerPermission(self, *, permission: ServerPermissionsEnum, userID: uuid.UUID,
                                  serverID: uuid.UUID) -> bool:

        permissions = await self._fetch(_SQL.hasServerPermission, permission,
                                        userID, serverID)

        try:
            hasPermission = bool(permissions[0])
        except IndexError:
            hasPermission = False

        return hasPermission

    async def changeChannelPermission(self, *, permission: ChannelPermissionEnum, value: bool,
                                      userID: uuid.UUID, channelID: uuid.UUID,
                                      actor: uuid.UUID) -> ChannelPermissions:

        permissions = await self._fetch(_SQL.changeChannelPermission,
                                        permission, value, userID, channelID,
                                        actor)

        if len(permissions) == 0:
            raise ActorNotAuthorized

        return ChannelPermissions.fromDict(permissions[0])



    async def changeServerPermission(self, *, permission: str, value: bool,
                                     userID: uuid.UUID, serverID: uuid.UUID,
                                     actor: uuid.UUID) -> ServerRegistration:

        permissions = await self._fetch(_SQL.changeServerPermission,
                                        permission, value, userID, serverID,
                                        actor)

        if len(permissions) == 0:
            raise ActorNotAuthorized

        return ServerRegistration.fromDict(permissions[0])

    async def sendMessage(self, *, content: str, userID: uuid.UUID,
                          channelID: uuid.UUID) -> Message:
        if len(content) >= 1000:
            raise MessageTooLong
        if not await self.hasChannelPermissions(channelID=channelID, permissions=[ChannelPermissionEnum.read, ChannelPermissionEnum.talk], userID=userID):
            raise ActorNotAuthorized

        message = (await self._fetch(_SQL.sendMessage, channelID, userID,
                                    content))[0]['sendmessage']

        parsedMessage = Message()
        parsedMessage.messageID = message[0]
        parsedMessage.messageID = message[1]
        parsedMessage.messageID = message[2]
        parsedMessage.messageID = message[3]
        parsedMessage.messageID = message[4]
        parsedMessage.messageID = message[5]

        return parsedMessage

    async def getChannel(self, *, channelID: uuid.UUID, userID: uuid.UUID) -> ChannelHistory:
        canReadHistory = await self.hasChannelPermission(permission=ChannelPermissionEnum.readHistory, userID=userID, channelID=channelID)
        if not canReadHistory:
            raise ActorNotAuthorized()

        rawChannel = await self._fetch('SELECT * FROM Channels WHERE channelID = $1', channelID)

        if len(rawChannel) == 0:
            raise NoSuchChannel()
        rawChannel = dict(rawChannel[0])


        history: List[Message] = []

        for message in await self._fetch('SELECT * FROM Messages WHERE channelID = $1 LIMIT 50 ORDER BY stamp DESC'):
            history.append(Message.fromDict(message))

        rawChannel['history'] = history
        channel = ChannelHistory.fromDict(rawChannel)

        return channel

    async def editMessage(self, *, messageID: int, userID: int,
                          content: str) -> Message:
        if len(content) >= 1000:
            raise MessageTooLong()

        message = await self._fetch(_SQL.editMessage, content, messageID,
                                    userID)
        return Message.fromDict(message[0])

    async def deleteMessage(self, *, messageID: uuid.UUID, userID: uuid.UUID,
                            channelID: uuid.UUID, actor: uuid.UUID) -> None:
        """Deletes a message

        Args:
            messageID (int):
            userID (int):
            channelID (int):
            actor (int):

        Raises:
            ActorNotAuthorized:
        """

        if not await self.isInServer(userID=actor, serverID=(await self.serverIDFromChannelID(channelID=channelID))):
            raise ActorNotAuthorized()

        if not (actor == userID or await self.hasChannelPermission(permission=ChannelPermissionEnum.deleteMessages, userID = actor, channelID = channelID)):
            raise ActorNotAuthorized()

        await self._execute(_SQL.deleteMessage, messageID)

    async def isInServer(self, *, userID: uuid.UUID, serverID: uuid.UUID) -> bool:
        """Checks to see if a user is in a server

        Args:
            userID (int):
            serverID (int):

        Returns:
            bool:
        """
        userID = await self._fetch('SELECT userID FROM ServerRegistration WHERE userID = $1 AND serverID = $2', userID, serverID)

        return len(userID) == 1

    async def serverIDFromChannelID(self, *, channelID: uuid.UUID) -> uuid.UUID:
        return (await self._fetch('SELECT serverID FROM channels WHERE channelID = $1', channelID))[0]['serverid'] #type: ignore

    async def addReaction(self, *, messageID: uuid.UUID, userID: uuid.UUID, channelID: uuid.UUID,
                          unicode: str) -> Reaction:
        """Adds a reaction to the database\n

        Args:\n
            messageID (int):\n
            userID (int):\n
            channelID (int):\n
            unicode (str):\n

        Raises:\n
            InvalidUnicode: The unicode argument is not a supported unicode alias.\n
            NoSuchMessage: messageID does not exist.\n
            ActorNotAuthorized: userID is not allowed to add reactions in this channel.\n
            NoSuchChannel: channelID does not exist.\n
        Returns:\n
            Reaction: Modified message object.\n
        """
        if unicode not in EMOJI_UNICODE.keys():
            raise InvalidUnicode()

        if len(await self._fetch('SELECT messageID FROM messages WHERE messageID = $1', messageID)) == 0:
            raise NoSuchMessage()

        if len(await self._fetch('SELECT channelID FROM Channels WHERE channelID = $1', channelID)) == 0:
            raise NoSuchChannel()

        if await self.hasChannelPermission(permission=ChannelPermissionEnum.addReactions, channelID=channelID, userID=userID):
            reaction = await self._fetch(_SQL.addReaction, messageID, userID,
                                        unicode)

            return Reaction.fromDict(reaction)
        else:
            raise ActorNotAuthorized()

    async def removeReaction(self, *, reactionID: uuid.UUID, userID: uuid.UUID, channelID: uuid.UUID) -> None:
        """Removes a reaction from the database\n

        Args:\n
            reactionID (int):\n
            userID (int):\n
            channelID (int):\n

        Raises:\n
            NoSuchReaction: reactionID is not valid.\n
            ActorNotAuthorized: Either the actor does not have the DeleteMessages permission, the user is no longer in the server, or the user does not own the message.\n
            NoSuchMessage: This should honestly never happen\n
        """
        try:
            reaction = Reaction.fromDict((await self._fetch('SELECT * FROM Reactions WHERE reactionID = $1', reactionID))[0])
        except IndexError:
            raise NoSuchReaction()
        try:
            #message = Message.fromDict((await self._fetch('SELECT * FROM Messages WHERE messageID = $1', reaction.))[0])
            raise NotImplementedError
        except IndexError:
            raise NoSuchMessage()
        if userID in reaction.users or await self.hasChannelPermission(permission=ChannelPermissionEnum.deleteMessages, channelID=channelID, userID=userID):
            await self._execute(_SQL.removeReaction1, reactionID)
            await self._execute(_SQL.removeReaction2, reactionID)
        else:
            raise ActorNotAuthorized()

    async def createChannel(self, *, serverID: uuid.UUID, name: str, userID: uuid.UUID) -> Channel:
        """Creates a new channel.

        Args:
            serverID (int):
            name (str):
            userID (int):

        Raises:
            ActorNotAuthorized: The actor does not have the addChannels permission.

        Returns:
            Channel: The newly created channel object.
        """

        if await self.hasServerPermission(permission=ServerPermissionsEnum.addChannels, userID = userID, serverID=serverID):
            channel = await self._fetch(_SQL.createChannel, name, serverID)
            return Channel.fromDict(channel[0])
        else:
            raise ActorNotAuthorized()

    async def changeSubscribedChannel(self, *, channelID: uuid.UUID, userID: uuid.UUID,
                                      sessionID: uuid.UUID) -> None:
        """Changes the channel a user is subscribed to in a session.

        Args:
            channelID (int):
            userID (int):
            sessionID (str):

        Raises:
            ActorNotAuthorized: The actor does not have the read permission.

        Returns:
            None:
        """
        if await self.hasChannelPermission(permission=ChannelPermissionEnum.read, userID=userID, channelID=channelID):
            return await self._execute(
                'UPDATE FocusedItems SET channelID = $1 WHERE userID = $2 and sessionID = $3',
                channelID, userID, sessionID)
        raise ActorNotAuthorized()

    async def getAllSessionsSubscribedToChannel(self, *, channelID: uuid.UUID): # type: ignore
        sessions = await self._fetch('SELECT sessionID FROM FocusedItems WHERE channelID = $1', channelID)
        for sessionID in sessions:
            yield sessionID[0]

    async def getAllSessionsSubscribedToServer(self, *, serverID: uuid.UUID): # type: ignore
        sessions = await self._fetch('SELECT sessionID FROM FocusedItems WHERE serverID = $1', serverID)
        for sessionID in sessions:
            yield sessionID[0]

    async def changeSubscribedServer(self, *, serverID: uuid.UUID, userID: uuid.UUID,
                                      sessionID: uuid.UUID) -> None:
        """Changes the channel a user is subscribed to in a session.

        Args:
            channelID (int):
            userID (int):
            sessionID (str):

        Raises:
            ActorNotAuthorized: The actor does not have the read permission.

        Returns:
            None:
        """
        if await self.isInServer(userID=userID, serverID=serverID):
            return await self._execute(
                'UPDATE FocusedItems SET serverID = $1 WHERE userID = $2 and sessionID = $3',
                serverID, userID, sessionID)
        raise ActorNotAuthorized()

class NoSuchMessage(Exception):
    pass

class NoSuchReaction(Exception):
    pass

class InvalidUnicode(Exception):
    pass

class CannotTalk(Exception):
    pass


class MessageTooLong(Exception):
    pass


class InvalidServerName(Exception):
    pass


class ActorNotAuthorized(Exception):
    pass


class UserNotFound(Exception):
    pass


class InvalidCredentials(Exception):
    pass


class UserExists(Exception):
    pass

class NoSuchChannel(Exception):
    pass
