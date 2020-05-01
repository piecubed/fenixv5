import unittest
from asyncTests import asyncTest
from fenix.database import Database, User, Server
from typing import Any, Dict, List, Callable, Awaitable
import functools
import traceback

_tests: Dict[int, List[Any]] = {}

def _addTest(position: int, name: str): #type: ignore
	def addTest(func): #type: ignore
		_tests[position] = [name, func]
		return func
	return addTest

class UserDatabaseTests(unittest.TestCase):

	database: Database = Database()
	async def createDatabase(self) -> None:
		with open('tables.psql', 'r') as f:
			await self.database._execute(f.read())

	@asyncTest
	async def testStart(self) -> None:
		for i in sorted(_tests):
			with self.subTest(test=_tests[i][0]):
				try:
					await (getattr(self, _tests[i][0]))()
				except Exception as e:
					self.fail(msg=''.join(traceback.format_tb(e.__traceback__)))
		await self.cleanUp()

	@_addTest(1, '_testLogin')
	async def _testLogin(self) -> None:
		await self.createDatabase()
		print(await self.database.signUp('test', 'testpassword', 'piesquared@gmail.com'))

	@_addTest(2, '_testFetchUser')
	async def _testFetchUser(self) -> None:
		await self.database.fetchUserByEmail('piesquared@gmail.com')

	@_addTest(3, '_testSignIn')
	async def _testSignIn(self) -> None:
		self.user = await self.database.signIn('piesquared@gmail.com', 'testpassword')

	@_addTest(4, '_testCreateServer')
	async def _testCreateServer(self) -> None:
		await self.database.createServer(1, 'Test')

	@_addTest(5, '_testJoinServer')
	async def _testJoinServer(self) -> None:
		await self.database.joinServer(1, 1)

	@_addTest(6, '_testSendMessage')
	async def _testSendMessage(self) -> None:
		await self.database.sendMessage('Test', 1, 1)

	@_addTest(7, '_testEditMessage')
	async def _testEditMessage(self) -> None:
		await self.database.editMessage(1, 1, 'EditTest')

	@_addTest(8, '_testAddReaction')
	async def _testAddReaction(self) -> None:
		await self.database.addReaction(1, 1, 1, '😄')

	@_addTest(9, '_testDeleteMessage')
	async def _testDeleteMessage(self) -> None:
		await self.database.joinServer(1, 1)

	async def cleanUp(self) -> None:
		await self.createDatabase()

if __name__ == '__main__':
	unittest.main()