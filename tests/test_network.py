import websockets

import tester


async def connect(base: str) -> None:
    await websockets.connect(base)

if __name__ == '__main__':
    Tester = tester.Tester()
    Tester.addAsyncTest('connect', connect('ws://localhost:2000')) # type: ignore
