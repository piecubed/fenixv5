import asyncio
import functools


def asyncTest(func): #type: ignore
    @functools.wraps(func)
    def wrapper(self): #type: ignore
        loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
        return loop.run_until_complete(func(self)) 
    return wrapper
