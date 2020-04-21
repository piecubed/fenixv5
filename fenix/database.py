import base64
import datetime
import hashlib
import secrets
from typing import Any, Dict, List

try:
    import fenix.conf as conf
    password = conf.databasePassword
except ImportError:
    password = 'test'

import asyncpg
from email_validator import EmailNotValidError, validate_email

# These are basically headers, since annotations are parsed weird


class User:

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

    @property
    def hasServers(self) -> bool:
        return self.servers is not None

    @property
    def isVerified(self) -> bool:
        return self.verified

    def checkPassword(self, password: bytes) -> bool:
        return secrets.compare_digest(AuthUtils.checkPassword(self.salt, password), self.password)

    def checkToken(self, token: str) -> bool:
        return self.token == token

    def isUser(self, id: int) -> bool:
        return self.id == id

    def __str__(self) -> str:
        return self.username

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'User':
        self = cls()
        self.id = int(source['uid'])
        self.username = str(source['username'])
        self.password = bytes(source['password'])
        self.email = str(source['email'])
        self.salt = bytes(source['salt'])
        self.settings = source['settings']
        self.token = str(source['token'])
        self.usernameHash = str(source['usernamehash'])
        self.createdAt = source['createdat']
        self.verified = bool(source['verified'])
        try:
            self.servers = source['servers']
        except KeyError:
            pass
        return self

class AuthUtils:
    @classmethod
    def checkPassword(cls, password: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha512', password, salt, 100000)


class Server:

    ID: int
    name: str
    createdAt: datetime.datetime
    settings: Dict[str, Any]

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Server':
        self = cls()
        self.ID = int(source['id'])
        self.name = str(source['name'])
        self.createdAt = source['createdat']
        if 'settings' in source.keys():
            self.settings = source['settings']
        return self

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
        
class Role:
    name: str
    color: str
    id: int

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Role':
        self = cls()
        self.name = str(source['name'])
        self.color = str(source['color'])
        self.id = int(source['id'])

        return self

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


class ServerRegistration:
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
        self = cls()
        self.userID = int(source['userID'])
        self.serverID = int(source['serverID'])
        self.roles = source['roles']
        self.addChannels = source['addChannels']
        self.assignRoles = source['assignRoles']
        self.kick = source['kick']
        self.ban = source['ban']
        self.changeNick = source['changeNick']
        self.changeOthersNick = source['changeOthersNick']
        return self

    @classmethod
    def fromListToList(cls, source: List[Dict[str, Any]]) -> List['ServerRegistration']:
        serverRegistration: List['ServerRegistration'] = []
        for raw in source:
            serverRegistration.append(cls.fromDict(raw))

        return serverRegistration
    
class ChannelPermissions:
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
    
    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'ChannelPermissions':
        self = cls()
        self.userID = source['userID']
        self.channelID = source['channelID']
        self.canRead = source['canRead']
        self.canTalk = source['canTalk']
        self.canReadHistory = source['canReadHistory']
        self.canDeleteMessages = source['canDeleteMessages']
        self.canManageChannel = source['canManageChannel']
        self.canManagePermissions = source['canManagePermissions']
        self.canPinMessages = source['canPinMessages']
        self.canMentionEveryone = source['canMentionEveryone']
        return self
    
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
    createRole = 'CASE WHEN (SELECT assignRoles FROM ServerRegistration WHERE serverID = $3 and userID = $4) = TRUE THEN INSERT INTO Roles (serverID, name, color) VALUES ($1, $2, $3) '
    getRole = 'SELECT * FROM Roles WHERE id = $1'
    createServer = 'INSERT INTO Servers (ownerID, createdAt, name) VALUES (CAST($1 AS INT), CURRENT_TIMESTAMP, $2) RETURNING id'
    addChannels = 'SELECT addChannels FROM ServerRegistration WHERE userID = $1 and serverID = $2'
    assignRoles = 'SELECT assignRoles FROM ServerRegistration WHERE userID = $1 and serverID = $2'
    kick = 'SELECT kick FROM ServerRegistration WHERE userID = $1 and serverID = $2'
    ban = 'SELECT ban FROM ServerRegistration WHERE userID = $1 and serverID = $2'
    changeNick = 'SELECT changeNick FROM ServerRegistration WHERE userID = $1 and serverID = $2'
    changeOthersNick = 'SELECT changeOthersNick FROM ServerRegistration WHERE userID = $1 and serverID = $2'
    canRead = 'SELECT canRead FROM ChannelPermissions WHERE userID = $1 and channelID = $2'
    canTalk = 'SELECT canTalk FROM ChannelPermissions WHERE userID = $1 and channelID = $2'
    canReadHistory = 'SELECT canReadHistory FROM ChannelPermissions WHERE userID = $1 and channelID = $2'
    canDeleteMessages = 'SELECT canDeleteMessages FROM ChannelPermissions WHERE userID = $1 and channelID = $2'
    canManageChannel = 'SELECT canManageChannel FROM ChannelPermissions WHERE userID = $1 and channelID = $2'
    canManagePermissions = 'SELECT canManagePermissions FROM ChannelPermissions WHERE userID = $1 and channelID = $2'
    canPinMessages = 'SELECT canPinMessages FROM ChannelPermissions WHERE userID = $1 and channelID = $2'
    canMentionEveryone = 'SELECT canMentionEveryone FROM ChannelPermissions WHERE userID = $1 and channelID = $2'
    letAddChannels = 'UPDATE ServerRegistration SET addChannels = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letAssignRoles = 'UPDATE ServerRegistration SET assignRoles = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letKick = 'UPDATE ServerRegistration SET kick = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letBan = 'UPDATE ServerRegistration SET ban = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letChangeNick = 'UPDATE ServerRegistration SET changeNick = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letChangeOthersNick = 'UPDATE ServerRegistration SET changeOthersNick = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letRead = 'UPDATE ServerRegistration SET canRead = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letTalk = 'UPDATE ServerRegistration SET canTalk = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letReadHistory = 'UPDATE ServerRegistration SET canReadHistory = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letDeleteMessages = 'UPDATE ServerRegistration SET canDeleteMessages = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letManageChannel = 'UPDATE ServerRegistration SET canManageChannel = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letManagePermissions = 'UPDATE ServerRegistration SET canManagePermissions = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letPinMessages = 'UPDATE ServerRegistration SET canPinMessages = $1 WHERE userID = $2 and serverID = $3 RETURNING *'
    letPingEveryone = 'UPDATE ServerRegistration SET canMentionEveryone = $1 WHERE userID = $2 and serverID = $3 RETURNING *'

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
    
    async def addChannels(self, userID: int, serverID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.addChannels, userID, serverID, permission))

    async def kick(self, userID: int, serverID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.kick, userID, serverID, permission))
    
    async def ban(self, userID: int, serverID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.ban, userID, serverID, permission))

    async def changeNick(self, userID: int, serverID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.changeNick, userID, serverID, permission))
    
    async def changeOthersNick(self, userID: int, serverID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.changeOthersNick, userID, serverID, permission))
    
    async def canRead(self, userID: int, channelID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.canRead, userID, channelID, permission))
    
    async def canTalk(self, userID: int, channelID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.canTalk, userID, channelID, permission))
    
    async def canReadHistory(self, userID: int, channelID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.canReadHistory, userID, channelID, permission))
    
    async def canDeleteMessages(self, userID: int, channelID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.canDeleteMessages, userID, channelID, permission))
    
    async def canManageChannel(self, userID: int, channelID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.canManageChannel, userID, channelID, permission))
    
    async def canManagePermissions(self, userID: int, channelID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.canManagePermissions, userID, channelID, permission))
    
    async def canPinMessages(self, userID: int, channelID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.canPinMessages, userID, channelID, permission))
    
    async def canMentionEveryone(self, userID: int, channelID: int, permission: str) -> bool:
        return bool(self._fetch(_SQL.canMentionEveryone, userID, channelID, permission))

    async def changeAddChannels(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letAddChannels, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeAssignRoles(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letAssignRoles, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeKick(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letKick, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeBan(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letBan, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeChangeNick(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letChangeNick, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeChangeOthersNick(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letChangeOthersNick, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeRead(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letRead, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeTalk(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letTalk, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeReadHistory(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letReadHistory, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeDeleteMessages(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letDeleteMessages, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changeManageChannel(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letManageChannel, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changePinMessages(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letPinMessages, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])
    
    async def changePingEveryone(self, value: bool, userID: int, serverID: int) -> List[ServerRegistration]:
        permissions = await self._fetch(_SQL.letPingEveryone, value, userID, serverID)
        return ServerRegistration.fromListToList(permissions[0])

   
class InvalidServerName(Exception):
    pass

class UserNotFound(Exception):
    pass

class InvalidCredentials(Exception):
    pass
