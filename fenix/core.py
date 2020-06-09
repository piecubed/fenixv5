import abc
import asyncio
import datetime
import http
import json
import uuid
from http import HTTPStatus
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

import websockets
import websockets.auth
import websockets.exceptions
from websockets.http import Headers

import fenix.database as database
from fenix._protocolCore import IncompletePacket
from fenix.connection import Connection
from fenix.extension import Extension
from fenix.extensions.main import MainExt
from fenix.protocol import *
from fenix.recaptcha import RECaptcha


class FenixCore:
    def __init__(self, extensions: Dict[str, Extension]) -> None:
        self.extensions.update(extensions)

    database = database.Database()
    recaptcha = RECaptcha()
    sessions: Dict[str, Connection] = {}
    extensions: Dict[str, Extension] = {
        None: MainExt() #type: ignore
    }

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
                code=1008, reason='https://www.xeroxirc.net/logs/#fenix?yyyy=2020&mm=04&dd=26&uhh=17&umm=53&sid=8&eid=26')

        try:
            focusedChannel = int(websocket.request_headers['focusedChannel'])
        except (ValueError, KeyError):
            return await websocket.close(
                code=1008, reason='No focusedChannel header present!')
        conn = Connection(websocket, user, self)

        # Add our sessionID
        await self.database.createSession(
                                               userID=user.userID,
                                               sessionID=conn.sessionID
                                              )
        self.sessions[conn.sessionID] = conn
        conn.main()

    async def handleHTTP(  #type: ignore
        self, path: str, request_headers: Headers
    ) -> Tuple[HTTPStatus, Union[Headers, Mapping[str, str], Iterable[Tuple[
            str, str]]], bytes]:
        status: HTTPStatus
        if path == "/token":
            try:
                token = request_headers['Token']
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

        elif path == "/signIn":
            try:
                email = request_headers['Email']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No email header present'
                return (status, headers, b'')

            try:
                password = request_headers['Password']
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
                password = request_headers['Password']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No password header present'
                return (status, headers, b'')

            try:
                email = request_headers['Email']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No email header present'
                return (status, headers, b'')

            try:
                username = request_headers['Username']
            except KeyError:
                status = HTTPStatus.BAD_REQUEST
                headers = Headers()
                headers['error'] = 'No username header present'
                return (status, headers, b'')

            # try:
            #     response = request_headers['Response']
            # except KeyError:
            #     status = HTTPStatus.BAD_REQUEST
            #     headers = Headers()
            #     headers['error'] = 'No response header present'
            #     return (status, headers, b'')

            # if not (await self.recaptcha.verify(response)):
            #     status = HTTPStatus.UNAUTHORIZED
            #     headers = Headers()
            #     headers['error'] = 'Invalid response token.'
            #     return (status, headers, b'')
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
        await websockets.serve(ws_handler=self.handleWebsocket, host='', )

    def run(self) -> None:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.connect())
        loop.run_forever()
