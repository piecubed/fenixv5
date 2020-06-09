import abc

from fenix.connection import Connection
from fenix.network import FenixCore
from fenix.protocol import BaseProtocol


class Extension(abc.ABC):
    @abc.abstractmethod
    def __init__(self, core: FenixCore) -> None:
        ...

    @abc.abstractmethod
    async def handle(self, message: BaseProtocol, conn: Connection) -> None:
        ...
