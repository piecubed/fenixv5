import abc
import asyncio
import datetime
import http
import json
from http import HTTPStatus
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

import websockets
import websockets.auth
from websockets.http import Headers

import fenix.database as database
from fenix._protocolCore import IncompletePacket
from fenix.protocol import *
from fenix.recaptcha import RECaptcha
import uuid


class MainExt(Extension):
    """
    Main extension that defines server interaction, message sending, and channel interaction.
    """
    def __init__(self, core: FenixCore) -> None:
        self.core: FenixCore = core
        self.database: database.Database = self.core.database

    async def changeSubscribedChannel(self, message: ChangeSubscribedChannel,
                                      conn: Connection) -> None:
        self.database.changeSubscribedChannel(channelID = message.channelID,
                                              userID = conn.user.userID, sessionID = conn.sessionID)

    async def handle(self, message: BaseProtocol, conn: Connection) -> None:
        pass


class Extension(abc.ABC):
    @abc.abstractmethod
    def __init__(self, core: FenixCore) -> None:
        ...

    @abc.abstractmethod
    async def handle(self, message: BaseProtocol, conn: Connection) -> None:
        ...


class Connection:
    def __init__(self, websocket: websockets.WebSocketServerProtocol,
                 user: database.User, core: FenixCore) -> None:
        self.ws = websocket
        self.user = user
        self.core = core
        self.sessionID: str = str(uuid.uuid4())

    async def send(self, payload: BaseProtocol) -> None:
        await self.ws.send(payload.dumps())

    async def main(self) -> None:
        try:
            focusedChannel = int(self.ws.request_headers['focusedChannel'])
        except (ValueError, KeyError):
            return await self.ws.close(
                code=1008, reason='No focusedChannel header present!')

        if focusedChannel == 0:
            focusedChannel = 1

        # Add our sessionID
        await self.core.database.createSession(
                                               userID=self.user.userID,
                                               sessionID=self.sessionID
                                              )

        # Our user should always be authenticated, so Fenix sends the fully authorized user.
        # Flow of authenticatsion would be something like this:
        # client sends HTTP upgrade request at /token, /password, /signUp with the appropiate headers.
        # If any of the headers are invalid, Fenix will abort the upgrade request, and return a HTTP error.
        # If all the headers are present, Fenix will attempt to authenticate for the specified user.
        # If authentication fails, Fenix will abort the upgrade reuqest, and return an HTTP error.
        # If authentication succeeds, Fenix will not return any HTTP header from our upgrade handler, and the connection will be
        # transformed into a websocket normally.
        # Fenix then gets the user object from the lingering HTTP headers accessible from the websocket object and sends a AuthUser
        # message to the client as the first message, and then starts listening.
        await self.send(AuthUser(self.user._raw))

        async for raw in self.ws:
            message: BaseProtocol
            try:
                messsage = clientMessages.get(json.loads(raw))
            except (TypeError, IncompletePacket, json.JSONDecodeError):
                await self.send(BadFormat({}))

            await self.core.extensions[message.extension].handle(message, self)


class FenixCore:
    database = database.Database()
    recaptcha = RECaptcha()
    connections: Dict[int, Connection] = {}
    extensions: Dict[str, Extension] = {}
    serverMessages = serverMessages
    clientMessages = clientMessages

    # Because of handleHTTP rejecting all connections that arent authenticated, we can safely
    # accept all connections here, and treat them as if they are logged in.
    async def handleWebsocket(self,
                              websocket: websockets.WebSocketServerProtocol,
                              path: str) -> None:
        user: database.User
        if path == '/password' or path == '/signUp':
            email = websocket.request_headers['email']
            user = await self.database.fetchUserByEmail(email=email)

        elif path == '/token':
            token = websocket.request_headers['token']
            user = await self.database.fetchUserByToken(token=token)
        else:
            print(path, 'got through the filter.')
            return await websocket.close(
                code=1008, reason='https://www.xeroxirc.net/logs/#fenix')

        self.connections[user.userID] = Connection(websocket, user, self)

        await self.connections[user.userID].main()

    async def handleHTTP(  #type: ignore
        self, path: str, request_headers: Headers
    ) -> Tuple[HTTPStatus, Union[Headers, Mapping[str, str], Iterable[Tuple[
            str, str]]], bytes]:
        status: HTTPStatus
        if path == "/token":
            try:
                token = request_headers['token']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No token header present'
                return (status, headers, b'')
            try:
                await self.database.tokenSignIn(token=token)
            except database.InvalidCredentials:
                status = HTTPStatus.UNAUTHORIZED
                headers = Headers()
                headers['error'] = 'Invalid token!'
                return (status, headers, b'')

        elif path == "/password":
            try:
                email = request_headers['email']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No email header present'
                return (status, headers, b'')

            try:
                password = request_headers['password']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No password header present'
                return (status, headers, b'')
            try:
                await self.database.signIn(email=email, password=password)
            except database.InvalidCredentials:
                status = HTTPStatus.UNAUTHORIZED
                headers = Headers()
                headers['error'] = 'Invalid token!'
                return (status, headers, b'')

        elif path == "/signUp":
            try:
                password = request_headers['password']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No password header present'
                return (status, headers, b'')

            try:
                email = request_headers['email']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No email header present'
                return (status, headers, b'')

            try:
                username = request_headers['username']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No username header present'
                return (status, headers, b'')

            try:
                response = request_headers['response']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No response header present'
                return (status, headers, b'')

            if not (await self.recaptcha.verify(response)):
                status = HTTPStatus.UNAUTHORIZED
                headers = Headers()
                headers['error'] = 'Invalid response token.'
                return (status, headers, b'')
            try:
                await self.database.signUp(username=username, password=password, email=email)
            except database.UserExists:
                status = HTTPStatus.FORBIDDEN
                headers = Headers()
                headers['error'] = 'Email is taken.'
                return (status, headers, b'')
        else:
            status = HTTPStatus.NOT_FOUND
            return (status, Headers(), b'')

    async def connect(self) -> None:
        websockets.serve(ws_handler=self.handleWebsocket)
