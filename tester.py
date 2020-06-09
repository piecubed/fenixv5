import asyncio
import traceback
import time
import functools
from typing import List, Dict, Any, Callable

class Tester:
    __tests: List[Dict[str, Any]] = []
    errors: List[str] = []

    def __run(self, func: Callable, name: str, asyncTest, args = [], kwargs = {}):
        t = time.time()
        if asyncTest:
            try:
                asyncio.get_event_loop().run_until_complete(func)
            except Exception as e:
                self.errors.append(name)
                return self.__formatError(f"Testing {name} failed! ({round(time.time() - t, 3)} seconds)", e)
        else:
            try:
                func(*args, **kwargs)
            except Exception as e:
                self.errors.append(name)
                return self.__formatError(f"Testing {name} failed! ({round(time.time() - t, 3)} seconds)", e)

        successNotice = f"{name} passed!"
        padding = ' ' * ((39 - len(successNotice)) // 2)
        div = "\u001b[32m|\u001b[0m"
        print("\u001b[32m========================================\u001b[0m")
        print(f"{div}{padding}{successNotice}{padding}{div}")
        print("\u001b[32m========================================\u001b[0m")

    def addAsyncTest(self, name: str, func: asyncio.Future) -> None:
        self.__tests.append({'func': func, 'name': name, 'async': True})

    def addSyncTest(self, name: str, func: Callable, *args, **kwargs) -> None:

        self.__tests.append({'func': func, 'name': name, 'async': False, 'args': args, 'kwargs': kwargs})

    def __formatError(self, failNotice, e) -> None:
        trace = ''.join(traceback.format_exception(type(e), e, e.__traceback__))

        split = trace.split('\n')
        split.sort(key=lambda target: len(target))

        longest = len(split[-1])

        paddingLeft = "  "
        divider = "\u001b[33m|\u001b[0m"
        heading = '=' * (longest + 6)
        noticePadding = ' ' * ((len(heading) - len(failNotice))//2)
        split = trace.split('\n')

        formattedLines = [
            f"\u001b[33m{heading}\u001b[0m",
            f"{divider}{noticePadding}\u001b[31m{failNotice}\u001b[0m{noticePadding[0:-3]} {divider}"
        ]

        for line in split:
            formattedLines.append(
                f"{divider}{paddingLeft}{line}{' ' * (longest - len(line) + 2)}{divider}"
            )
        formattedLines.append(f"\u001b[33m{heading}\u001b[0m")

        print()
        for line in formattedLines:
            print(line)

    def run(self) -> None:
        asyncio.new_event_loop()
        t = time.time()
        for test in self.__tests:
            print()
            if test['async']:
                self.__run(test['func'], test['name'], True)
            else:
                self.__run(test['func'], test['name'], False, args=test['args'], kwargs=test['kwargs'])
        end = time.time()

        print("\nTook", round(end-t, 3), "seconds!\n")
        if len(self.errors) == 0:

            print(
"""\u001b[32m
=========================================
|            All tests pass!            |
=========================================\u001b[0m
""" )
        else:
            notice = f"{len(self.errors)}/{len(self.__tests)} failed!"
            padding = ' ' * ((39 - len(notice)) // 2)
            div = "|"
            print("\u001b[31m=========================================")
            print(f"{div}{padding}{notice}{padding}{div}")
            print("=========================================\u001b[0m")
