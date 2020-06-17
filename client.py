from fenix import protocol
import asyncio
import websockets.client

class Client:
    websocket: websockets.WebSocketClientProtocol

    async def listenForKeyBoardInput(self):
        while True:
            message = input('>>>')
            await self.sendMessage(message)
    
    async def __new__(cls) -> 'Awaitable[Client]': #type: ignore
        self = cls()
        self.websocket = await websockets.client.connect('ws://bloblet.com:43618/token', extra_headers={'Token': ''})
        return self



