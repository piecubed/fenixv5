#!/usr/bin/env python3
#
# Protocol message helpers
#
# Copyright © 2020 by luk3yx
#

import copy
from typing import (Any, Callable, Dict, Iterable, Iterator, List, Optional,
                    Type, Union, get_type_hints)

class _AutoSlotsMeta(type):
    """
    Automatically adds __slots__ to classes if possible.
    """

    __slots__ = ()
    def __new__(cls, *args): # type: ignore
        if len(args) == 3 and isinstance(args[2], dict):
            d = args[2]
            if '__slots__' not in d:
                annotations = d.get('__annotations__', ())
                for var in annotations:
                    if var in d:
                        break
                else:
                    d['__slots__'] = tuple(annotations)
        res = super().__new__(cls, *args)
        hints = get_type_hints(res)
        hints = {k: v for k, v in hints.items() if not k.startswith('_')}
        res._BaseMessage__annotations = hints # type: ignore
        return res

def _isinstance(obj: Any, typ: Any) -> bool:
    """
    A custom isinstance() which handles typing.Union, typing.List and
    typing.Dict.
    """

    if typ is Any:
        return True
    if not hasattr(typ, '__origin__'):
        if typ is float:
            return isinstance(obj, (int, float))
        return isinstance(obj, typ)

    if typ.__origin__ is Union:
        return any(_isinstance(obj, i) for i in typ.__args__)
    if typ.__origin__ is list:
        if not isinstance(obj, list):
            return False

        # This is not a typo, the comma unpacks __args__ and ensures it only
        # contains one element.
        t, = typ.__args__

        return all(_isinstance(i, t) for i in obj)
    if typ.__origin__ is dict:
        if not isinstance(obj, dict):
            return False

        kt, vt = typ.__args__
        for k, v in obj.items():
            if not _isinstance(k, kt) or not _isinstance(v, vt):
                return False
        return True

    raise NotImplementedError(typ)


class BaseMessage(metaclass=_AutoSlotsMeta):
    """
    Creates a message class.
    """

    __annotations: Dict[str, Any]
    def __init__(self, data: Dict[Any, Any]) -> None:
        assert isinstance(data, dict)
        for attr, attr_type in self.__annotations.items():
            if attr not in data:
                if not hasattr(self, attr):
                    raise KeyError(attr)
                setattr(self, attr, copy.deepcopy(getattr(self, attr)))
                continue

            value = data[attr]
            if not _isinstance(value, attr_type):
                raise TypeError(f'Expected {attr_type!r}, got {value!r}')
            setattr(self, attr, value)

    def __iter__(self) -> Iterator[Any]:
        for attr in self.__class__.__annotations:
            yield getattr(self, attr)

class ProtocolHelper:
    __slots__ = ('types',)
    def __init__(self) -> None:
        self.types: Dict[str, Type[BaseMessage]] = {}

    def add(self, *names: str) -> Callable[[Type[BaseMessage]],
            Type[BaseMessage]]:
        """
        A decorator to add packet types.
        @protocolHelper.add('hello')
        class _Hello(BaseMessage):
            world: str
        """
        def wrapper(cls: Type[BaseMessage]) -> Type[BaseMessage]:
            for name in names:
                self.types[name] = cls
            return cls
        return wrapper

    def get(self, packet: Dict[Any, Any]) -> Optional[BaseMessage]:
        """
        Gets a packet object of the correct type for a certain packet. Returns
        None if the packet type doesn't exist.
        """
        try:
            typ = self.types[packet['type']]
        except KeyError:
            return None

        return typ(packet)
