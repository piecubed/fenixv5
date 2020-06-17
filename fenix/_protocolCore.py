#!/usr/bin/env python3
#
# Protocol message helpers
#
# Copyright © 2020 by luk3yx and piesquared
#

import copy
from typing import (Any, Callable, Dict, Iterable, Iterator, List, Optional,
                    Type, Union, get_type_hints)
import json
import uuid


class _AutoSlotsMeta(type):
    """
	Automatically adds __slots__ to classes if possible.
	"""

    __slots__ = ()

    def __new__(cls, *args):  # type: ignore
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
        res._BaseMessage__annotations = hints  # type: ignore
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
    id: Optional[int]
    _raw: Dict[str, Any]

    def dumps(self) -> str:
        raw = {}
        for attr, attr_type in self.__annotations.items():
            if attr_type == uuid.UUID:
                id: uuid.UUID = getattr(self, attr)
                raw[attr] = str(id)
            else:
                raw[attr] = getattr(self, attr)

        return json.dumps(raw)

    def __init__(self, data: Dict[Any, Any]) -> None:
        self.extension: str
        actualData: Dict[str, Any] = {}
        assert isinstance(data, dict)
        for attr, attr_type in self.__annotations.items():
            if attr not in data and _isinstance(attr_type, Optional[Any]):
                continue

            if attr not in data:
                if not hasattr(self, attr):
                    print(data)
                    raise IncompletePacket(attr)
                actualData[attr] = copy.deepcopy(getattr(self, attr))
                setattr(self, attr, copy.deepcopy(getattr(self, attr)))
                continue

            value = data[attr]
            if attr_type == uuid.UUID:
                value = uuid.UUID(value)

            if not _isinstance(value, attr_type):
                raise TypeError(f'Expected {attr_type!r}, got {value!r} for {attr}')
            actualData[attr] = value
            setattr(self, attr, value)

        self._raw = actualData
        self._raw['type'] = str(self.__class__).split('.')[-1].split("'")[0]

    def __iter__(self) -> Iterator[Any]:
        for attr in self.__class__.__annotations:
            yield getattr(self, attr)

class ProtocolHelper:
    __slots__ = ('types', )

    def __init__(self) -> None:
        self.types: Dict[str, Type[BaseMessage]] = {}

    def add(
        self,
        *names: str,
        extension: str = 'main'
    ) -> Callable[[Type[BaseMessage]], Type[BaseMessage]]:
        """
		A decorator to add packet types.
		```
		@protocolHelper.add('hello')
		class _Hello(BaseMessage):
			world: str
		```
		"""
        def wrapper(cls: Type[BaseMessage]) -> Type[BaseMessage]:
            for name in names:
                self.types[name] = cls
                cls.extension = extension
            return cls

        return wrapper

    def get(self, packet: Dict[Any, Any]) -> BaseMessage:
        """
		Gets a packet object of the correct type for a certain packet. Raises a typeError if the type doesnt exist.
		"""
        try:
            typ = self.types[packet['type']]
        except KeyError:
            raise TypeError

        return typ(packet)


class IncompletePacket(Exception):
    pass
