from __future__ import annotations
import fenix.core as core
import fenix.protocol as protocol
import fenix.connection as connection
import abc

class Extension(abc.ABC):
    @abc.abstractmethod
    def __init__(self, core: core.FenixCore) -> None:
        ...

    @abc.abstractmethod
    async def handle(self, message: protocol.BaseProtocol, conn: connection.Connection) -> None:
        ...