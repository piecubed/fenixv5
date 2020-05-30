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

class MainExt(Extension):
    """
    Main extension that defines server interaction, message sending, and channel interaction.
    """

    def __init__(self, core: FenixCore) -> None:
        self.core = core

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
    def __init__(self, websocket: websockets.WebSocketServerProtocol, user: database.User, core: FenixCore) -> None:
        self.ws = websocket
        self.user = user
        self.core = core

    async def send(self, payload: BaseProtocol) -> None:
        await self.ws.send(payload.dumps())

    async def main(self) -> None:
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
    async def handleWebsocket(self, websocket: websockets.WebSocketServerProtocol, path: str) -> None:
        if path == '/password' or path == '/signUp':
            email = websocket.request_headers['email']
            user: database.User = await self.database.fetchUserByEmail(email)

        elif path == '/token':
            token = websocket.request_headers['token']
            user: database.User = await self.database.fetchUserByToken(token) #type: ignore
        else:
            print(path, 'got through the filter.')
            return await websocket.close(code=1008, reason='https://www.xeroxirc.net/logs/#fenix')

        self.connections[user.userID] = Connection(websocket, user, self)

        await self.connections[user.userID].main()


    async def handleHTTP(self, path: str, request_headers: Headers) -> Tuple[HTTPStatus, Union[Headers, Mapping[str, str], Iterable[Tuple[str, str]]], bytes]: # type: ignore
        if path == "/token":
            try:
                token = request_headers['token']
            except KeyError:
                status: HTTPStatus = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No token header present'
                return (status, headers, b'')
            try:
                await self.database.tokenSignIn(token)
            except database.InvalidCredentials:
                status: HTTPStatus = HTTPStatus.UNAUTHORIZED #type: ignore
                headers = Headers()
                headers['error'] = 'Invalid token!'
                return (status, headers, b'')

        elif path == "/password":
            try:
                email = request_headers['email']
            except KeyError:
                status: HTTPStatus = HTTPStatus.BAD_REQUEST #type: ignore
                headers = Headers()
                headers['error'] = 'No email header present'
                return (status, headers, b'')

            try:
                password = request_headers['password']
            except KeyError:
                status: HTTPStatus = HTTPStatus.BAD_REQUEST #type: ignore
                headers = Headers()
                headers['error'] = 'No password header present'
                return (status, headers, b'')
            try:
                await self.database.signIn(email, password)
            except database.InvalidCredentials:
                status: HTTPStatus = HTTPStatus.UNAUTHORIZED #type: ignore
                headers = Headers()
                headers['error'] = 'Invalid token!'
                return (status, headers, b'')

        elif path == "/signUp":
            try:
                password = request_headers['password']
            except KeyError:
                status: HTTPStatus = HTTPStatus.BAD_REQUEST #type: ignore
                headers = Headers()
                headers['error'] = 'No password header present'
                return (status, headers, b'')

            try:
                email = request_headers['email']
            except KeyError:
                status: HTTPStatus = HTTPStatus.BAD_REQUEST #type: ignore
                headers = Headers()
                headers['error'] = 'No email header present'
                return (status, headers, b'')

            try:
                username = request_headers['username']
            except KeyError:
                status: HTTPStatus = HTTPStatus.BAD_REQUEST #type: ignore
                headers = Headers()
                headers['error'] = 'No username header present'
                return (status, headers, b'')

            try:
                response = request_headers['response']
            except KeyError:
                status: HTTPStatus = HTTPStatus.BAD_REQUEST #type: ignore
                headers = Headers()
                headers['error'] = 'No response header present'
                return (status, headers, b'')

            if not (await self.recaptcha.verify(response)):
                status: HTTPStatus = HTTPStatus.UNAUTHORIZED #type: ignore
                headers = Headers()
                headers['error'] = 'Invalid response token.'
                return (status, headers, b'')
            try:
                await self.database.signUp(username, password, email)
            except database.UserExists:
                status: HTTPStatus = HTTPStatus.FORBIDDEN #type: ignore
                headers = Headers()
                headers['error'] = 'Email is taken.'
                return (status, headers, b'')
        else:
            status: HTTPStatus = HTTPStatus.NOT_FOUND #type: ignore
            return (status, Headers(), b'')




    async def connect(self) -> None:
        websockets.serve(ws_handler=self.handleWebsocket)
