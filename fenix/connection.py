import json
import uuid
from typing import Optional

import websockets

from fenix import database
from fenix._protocolCore import IncompletePacket
from fenix.core import FenixCore
from fenix.protocol import *


class Connection:
    def __init__(self, websocket: websockets.WebSocketServerProtocol,
                 user: database.User, core: FenixCore) -> None:
        self.ws = websocket
        self.user = user
        self.core = core
        self.sessionID: str = str(uuid.uuid4())

    async def send(self, payload: BaseProtocol, original: Optional[BaseProtocol] = None) -> None:
        if original is None:
            try:
                await self.ws.send(payload.dumps())
            except websockets.exceptions.ConnectionClosed:
                del self
        else:
            payload.id = original.id
            try:
                await self.ws.send(payload)
            except websockets.exceptions.ConnectionClosed:
                del self

    async def main(self) -> None:
        try:
            focusedChannel = int(self.ws.request_headers['focusedChannel'])
        except (ValueError, KeyError):
            return await self.ws.close(
                code=1008, reason='No focusedChannel header present!')

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
        await self.send(AuthUser(self.user._raw), original=BaseProtocol({'id': 0}))
        if focusedChannel != 0:
            channel: database.ChannelHistory = await self.core.database.getChannel(channelID=focusedChannel, userID=self.user.userID)
            await self.send(ChannelInfo(channel._raw), original=BaseProtocol({'id': 1}))

        async for raw in self.ws:
            message: BaseProtocol
            try:
                messsage = clientMessages.get(json.loads(raw))
            except (TypeError, IncompletePacket, json.JSONDecodeError):
                await self.send(BadFormat({}))

            await self.core.extensions[message.extension].handle(message, self)
