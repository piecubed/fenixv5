import base64
import datetime
import hashlib
import secrets
from typing import Any, Dict, List

try:
    import fenix.conf as conf
except ImportError:
    print('conf.py is required.')
    exit()

import asyncpg
from email_validator import EmailNotValidError, validate_email

# These are basically headers, since annotations are parsed weird


class User:

    uid: str
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

    def isUser(self, uid: str) -> bool:
        return self.uid == uid

    def __str__(self) -> str:
        return self.username

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'User':
        self = cls()
        self.uid = str(source['uid'])
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

    ID: str
    name: str
    createdAt: datetime.datetime
    settings: Dict[str, Any]

    @classmethod
    def fromDict(cls, source: Dict[str, Any]) -> 'Server':
        self = cls()
        self.ID = str(source['id'])
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
        self.name = str(source['name'])
        self.id = int(source['id'])

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
        self.name = str(source['name'])
        self.color = str(source['color'])
        self.id = str(source['id'])

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
        self.__databaseUrl: str = databaseUrl

    __pool: asyncpg.Connection = None

    async def __connect(self) -> None:
        self.__pool: asyncpg.Connection = await asyncpg.create_pool(self.__databaseUrl, password=conf.databasePassword)

    async def _execute(self, statement: str, *bindings: Any) -> None:
        if self.__pool is None:
            await self.__connect()

        await self.__pool.execute(statement, *bindings) #type: ignore

    async def _fetch(self, statement: str, *bindings: Any) -> asyncpg.Record:
        if self.__pool is None:
            await self.__connect()

        return await self.__pool.fetch(statement, *bindings) #type: ignore

class _UsersSQL:
    fetchUserByEmail = 'SELECT * FROM Users WHERE email = $1'
    signUp = 'INSERT INTO Users(username, password, email, salt, token, createdAt, verified) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, TRUE) RETURNING *'
    getServers = 'SELECT * FROM ServerRegistration INNER JOIN Servers ON ServerRegistration.userID = CAST($1 AS INT)' \
        'and Servers.id = ServerRegistration.serverID'
    signIn = 'SELECT * FROM Users WHERE email = $1 and password = $2'
    getPerms = 'SELECT * FROM ServerPermissions WHERE userID = CAST($1 AS INT) and serverID = CAST($2 AS INT)'
    getRoles = 'SELECT ServerRegistration.Roles FROM ServerRegistration INNER JOIN Roles ON '\
        'ServerRegistration.userID = CAST($1 AS INT) AND ServerRegistration.serverID = CAST($2 AS INT) AND Roles.id = ANY(ServerRegistration.roles)'
    joinServer = 'INSERT INTO ServerRegistration(userID, serverID) VALUES ($1, $2)'
    getServer = 'SELECT * FROM Servers WHERE id = $1'

class Users(Database):

    async def fetchUserByEmail(self, email: str) -> User:
        query = await self._fetch(_UsersSQL.fetchUserByEmail, email)
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

        user = await self._fetch(_UsersSQL.signUp, username, hash, email, salt, token)

        return User.fromDict(user[0])

    async def signIn(self, email: str, password: str) -> User:
        user: User = await self.fetchUserByEmail(email)

        hash: bytes = AuthUtils.checkPassword(password.encode('utf-8'), user.salt)

        if not secrets.compare_digest(hash, user.password):
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

    async def joinServer(self, userID: str, serverID: str) -> Server:
        await self._execute(_UsersSQL.joinServer, userID, serverID)
        server = await self._fetch(_UsersSQL.getServer, int(serverID))

        return Server.fromDict(server[0])

    async def joinRole(self, userID: str, serverID: str, roleID: str) -> Role:
        raise NotImplementedError

class _ServerSQL:
    createServer = 'INSERT INTO Servers (ownerID, createdAt, name) VALUES (CAST($1 AS INT), CURRENT_TIMESTAMP, $2) RETURNING id'
    getServer = 'SELECT * FROM Servers WHERE id = CAST($1 AS INT)'


class Servers(Database):

    def validate(self, name: str) -> None:
        if len(name) > 40:
            raise InvalidServerName

    async def getServer(self, serverID: str) -> Server:
        server = await self._fetch(_ServerSQL.getServer, serverID)
        return Server.fromDict(server[0])

    async def createServer(self, userID: str, name: str) -> Server:
        self.validate(name)

        serverID = await self._fetch(_ServerSQL.createServer, int(userID), name)
        server = await self.getServer(serverID[0]['id'])

        return server

class InvalidServerName(Exception):
    pass

class UserNotFound(Exception):
    pass

class InvalidCredentials(Exception):
    pass
