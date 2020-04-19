import base64
import datetime
import hashlib
import secrets
from typing import Any, Dict, List

import asyncpg
from email_validator import EmailNotValidError, validate_email

# These are basically headers, since annotations are parsed weird


class User:

    uid: str
    username: str
    password: bytearray
    email: str
    salt: bytearray
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

    def isUser(self, uid: str) -> bool:
        return self.uid == uid

    def __str__(self) -> str:
        return self.username

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'User':
        self = cls()
        self.uid = source['uid']
        self.username = source['username']
        self.password = source['password']
        self.email = source['email']
        self.salt = source['salt']
        self.settings = source['settings']
        self.token = source['token']
        self.usernameHash = source['usernameHash']
        self.createdAt = source['createdAt']
        self.verified = source['verified']
        try:
            self.servers = source['servers']
        except KeyError:
            pass
        return self

class AuthUtils:
    @classmethod
    def checkPassword(cls, password: bytes, salt: bytes) -> bytearray:
        return bytearray(base64.b64encode(hashlib.pbkdf2_hmac('sha512', password, salt, 100000)))


class Server:

    ID: str
    name: str
    createdAt: datetime.datetime
    settings: Dict[str, Any]

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Server':
        self = cls()
        self.ID = source['id']
        self.name = source['name']
        self.createdAt = source['createdAt']
        self.settings = source['settings']
        return self

    @classmethod
    def fromListToList(cls, source: List[Dict[str, Any]]) -> List['Server']:
        servers: List['Server'] = []
        for raw in source:
            servers.append(cls.fromDict(raw))

        return servers

    @classmethod
    def fromListToDict(cls, source: List[Dict[str, Any]]) -> Dict[str, 'Server']:
        servers: Dict[str, 'Server'] = {}
        for raw in source:
            server = cls.fromDict(raw)
            servers[server.ID] = server

        return servers


class Permission:
    name: str
    id: int

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Permission':
        self = cls()
        self.name = source['name']
        self.id = source['id']

        return self

    @classmethod
    def fromListToList(cls, source: List[Dict[str, Any]]) -> List['Permission']:
        permissions: List['Permission'] = []
        for raw in source:
            permissions.append(cls.fromDict(raw))

        return permissions

    @classmethod
    def fromListToDict(cls, source: List[Dict[str, Any]]) -> Dict[int, 'Permission']:
        permissions: Dict[int, 'Permission'] = {}
        for raw in source:
            permission = cls.fromDict(raw)
            permissions[permission.id] = permission

        return permissions


class Role:
    name: str
    color: str
    id: str

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Role':
        self = cls()
        self.name = source['name']
        self.color = source['color']
        self.id = source['id']

        return self

    @classmethod
    def fromListToDict(cls, source: List[Dict[str, Any]]) -> Dict[str, 'Role']:
        roles: Dict[str, 'Role'] = {}
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

class Database:

    def __init__(self, databaseUrl: str = 'postgresql://piesquared@localhost:5432/fenix') -> None:
        self._databaseUrl: str = databaseUrl

    _pool: asyncpg.Connection

    async def _connect(self) -> None:
        self._pool: asyncpg.Connection = await asyncpg.create_pool(self._databaseUrl)

    async def _execute(self, statement: str, *bindings: Any) -> None:
        if self._pool is None:
            await self._connect()

        await self._pool.execute(statement, *bindings) #type: ignore

    async def _fetch(self, statement: str, *bindings: Any) -> asyncpg.Record:

        if self._pool is None:
            await self._connect()
        return await self._pool.fetch(statement, *bindings) #type: ignore

class _UsersSQL:
    fetchUserByEmail = 'SELECT * FROM Users WHERE email = $1'
    signUp = 'INSERT INTO Users (username, password, email, salt, settings, token, createdAt, verified)' \
        'VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIME, 1)'
    getServers = 'SELECT * FROM ServerRegistration INNER JOIN Servers ON ServerRegistration.userID = $1' \
        'and Servers.id = ServerRegistration.serverID'
    getPerms = 'SELECT * FROM ServerPermissions WHERE userID = $1 and serverID = $2'
    getRoles = 'SELECT ServerRegistration.Roles FROM ServerRegistration INNER JOIN Roles ON '\
        'ServerRegistration.userID = $1 AND ServerRegistration.serverID = $2 AND Roles.id = ANY(ServerRegistration.roles)'

class Users(Database):

    async def fetchUserByEmail(self, email: str) -> User:
        query = (await self._fetch(_UsersSQL.fetchUserByEmail))[0]
        try:
            return User.fromDict(query)
        except KeyError:
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

    async def signUp(self, username: str, password: bytes, email: str) -> User:
        await self.__validate(username, password, email)

        salt = base64.b64encode(secrets.token_hex(32).encode('utf-8'))
        token = base64.b64encode(secrets.token_hex(128).encode('utf-8')).decode('utf-8')
        password = AuthUtils.checkPassword(password, salt)

        self._execute(_UsersSQL.signUp, username, password, email, salt, '{}', token)

        return await self.fetchUserByEmail(email)

    async def signIn(self, email: str, password: str) -> User:
        user: User = await self.fetchUserByEmail(email)

        if not user.checkPassword(user.password):
            raise InvalidCredentials

        return user

    async def getServers(self, id: str) -> Dict[str, Server]:
        servers = await self._fetch(_UsersSQL.getServers, id)

        try:
            return Server.fromListToDict(servers)

        except KeyError:
            return {}

    async def getPerms(self, userID: str, serverID: str) -> Dict[int, Permission]:
        perms = await self._fetch(_UsersSQL.getPerms, userID, serverID)
        return Permission.fromListToDict(perms)

    async def getRoles(self, userID: str, serverID: str) -> Dict[str, Role]:
        roles = await self._fetch(_UsersSQL.getRoles, userID, serverID)

        try:
            return Role.fromListToDict(roles)

        except KeyError:
            return {}

    async def getServersList(self, id: str) -> List[Server]:
        servers = await self._fetch(_UsersSQL.getServers, id)

        try:
            return Server.fromListToList(servers)

        except KeyError:
            return []

    async def getPermsList(self, userID: str, serverID: str) -> List[Permission]:
        perms = await self._fetch(_UsersSQL.getPerms, userID, serverID)
        return Permission.fromListToList(perms)

    async def getRolesList(self, userID: str, serverID: str) -> List[Role]:
        roles = await self._fetch(_UsersSQL.getRoles, userID, serverID)

        try:
            return Role.fromListToList(roles)

        except KeyError:
            return []


class _ServerSQL:
    createServer = 'INSERT INTO Servers (ownerID, createdAt, name) VALUES ($1, current_time, $2) RETURNING id'
    getServer = 'SELECT * FROM Servers WHERE id = $1'


class Servers(Database):

    def validate(self, name: str) -> None:
        if len(name) > 40:
            raise InvalidServerName

    async def getServer(self, serverID: str) -> Server:
        server = await self._fetch(_ServerSQL.getServer, serverID)
        return Server.fromDict(server[0])

    async def createServer(self, userID: str, name: str) -> Server:
        self.validate(name)

        serverID = await self._fetch(_ServerSQL.createServer, userID, name)
        server = await self.getServer(serverID[0])

        return server

class InvalidServerName(Exception):
    pass

class UserNotFound(Exception):
    pass

class InvalidCredentials(Exception):
    pass
