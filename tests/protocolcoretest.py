import typing
import unittest

from fenix._protocol_core import BaseMessage, _isinstance


class ProtocolCoreTest(unittest.TestCase):
	def test_isinstance(self) -> None:
		self.assertTrue(_isinstance(object(), typing.Any))
		self.assertTrue(_isinstance([], typing.List[str]))
		self.assertTrue(_isinstance([1, 2, 3], typing.List[int]))
		self.assertFalse(_isinstance([1, 2, '3'], typing.List[int]))
		self.assertTrue(_isinstance([{'test': 123}, {'test2': 456}],
			typing.List[typing.Dict[str, int]]))

	def test_basemessage(self) -> None:
		class Test(BaseMessage):
			a: int
			b: str
			_ignore_me: bool
			c: typing.List['int']

		self.assertEqual(Test.__slots__, ('a', 'b', '_ignore_me', 'c'))
		self.assertEqual(Test._BaseMessage__annotations, {
			'a': int,
			'b': str,
			'c': typing.List[int],
		})

		self.assertRaises(KeyError, lambda : Test({'a': 5}))
		self.assertRaises(TypeError, lambda : Test({'a': '6'}))
		self.assertEqual(tuple(Test({'a': 5, 'b': '6', 'c': [7]})),
			(5, '6', [7]))

		class Test2(BaseMessage):
			a: int = 6
			b: str

		obj = Test2({'b': '5'})
		self.assertEqual(tuple(obj), (6, '5'))
		self.assertEqual(obj.__dict__, {'a': 6, 'b': '5'})

if __name__ == '__main__':
	unittest.main()
