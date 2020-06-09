import unittest

from asyncTests import asyncTest
from fenix.database import Database, Server, User


class UserDatabaseTests(unittest.TestCase):

	database: Database = Database()
	async def createDatabase(self) -> None:
		with open('tables.psql', 'r') as f:
			await self.database._execute(f.read())


	@asyncTest
	async def test001(self) -> None:
		await self.createDatabase()
		print(await self.database.signUp('test', 'testpassword', 'piesquared@gmail.com'))

	@asyncTest
	async def test002(self) -> None:
		await self.database.fetchUserByEmail('piesquared@gmail.com')

	@asyncTest
	async def test003(self) -> None:
		self.user = await self.database.signIn('piesquared@gmail.com', 'testpassword')

	@asyncTest
	async def test004(self) -> None:
		await self.database.createServer(1, 'Test')

	@asyncTest
	async def test005(self) -> None:
		await self.database.joinServer(1, 1)

	@asyncTest
	async def test006(self) -> None:
		await self.database.sendMessage('Test', 1, 1)

	@asyncTest
	async def test007(self) -> None:
		await self.database.joinServer(1, 1)


	@asyncTest
	async def test008(self) -> None:
		await self.database.joinServer(1, 1)

	@asyncTest
	async def test009(self) -> None:
		await self.database.joinServer(1, 1)


	@asyncTest
	async def test010(self) -> None:
		await self.database.joinServer(1, 1)


if __name__ == '__main__':
	unittest.main()
