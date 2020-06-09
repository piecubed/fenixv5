from fenix import database
from fenix.connection import Connection
from fenix.core import FenixCore
from fenix.extension import Extension
from fenix.protocol import *


class MainExt(Extension):
    """
    Main extension that defines server interaction, message sending, and channel interaction.
    """

    def __init__(self, core: FenixCore) -> None:
        self.core: FenixCore = core
        self.database: database.Database = self.core.database

    async def changeSubscribedChannel(self, message: ChangeSubscribedChannel,
                                      conn: Connection) -> None:
        try:
            await self.database.changeSubscribedChannel(**message._raw)
            channel: database.ChannelHistory = await self.database.getChannel(channelID=message.channelID, userID=conn.user.userID)
            await conn.send(ChannelInfo(channel._raw), original=message)
        except database.ActorNotAuthorized:
            await conn.send(ActorNotAuthorized({}), original=message)

    async def createChannel(self, message: CreateChannel, conn: Connection) -> None:
        try:
            await conn.send(ChannelInfo((await self.database.createChannel(**message._raw))._raw), original=message)
        except database.ActorNotAuthorized:
            await conn.send(payload=ActorNotAuthorized({}), original=message)

    async def sendMessage(self, message: SendMessage, conn: Connection) -> None:
        try:
            messageToSend: database.Message = await self.database.sendMessage(content=message.contents, userID=conn.user.userID, channelID=message.channelID)
        except database.MessageTooLong:
            await conn.send(MessageError({}), original=message)
        except database.ActorNotAuthorized:
            await conn.send(ActorNotAuthorized({}), original=message)

        async for sessionID in self.database.getAllSessionsSubscribedToChannel(channelID=message.channelID):
            await self.core.sessions[sessionID].send(SentMessage(messageToSend._raw))


    async def handle(self, message: BaseProtocol, conn: Connection) -> None:
        pass
