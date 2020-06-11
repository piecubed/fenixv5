import unittest

from asyncTests import asyncTest
from fenix.database import Database, Server, User
import uuid

class UserDatabaseTests(unittest.TestCase):

	database: Database = Database()
	sessionID = str(uuid.uuid4())
	async def createDatabase(self) -> None:
		with open('tables.psql', 'r') as f:
			await self.database._execute(f.read())


	@asyncTest
	async def test001(self) -> None:
		await self.createDatabase()
		await self.database.signUp(username='test', password='testpassword', email='piesquared@gmail.com')

	@asyncTest
	async def test002(self) -> None:
		await self.database.fetchUserByEmail(email='piesquared@gmail.com')

	@asyncTest
	async def test003(self) -> None:
		self.user = await self.database.signIn(email='piesquared@gmail.com', password='testpassword')

	@asyncTest
	async def test004(self) -> None:
		await self.database.createSession(userID=1, sessionID=self.sessionID)

	@asyncTest
	async def test005(self) -> None:
		await self.database.createServer(userID=1, name='Test', sessionID=self.sessionID)

	@asyncTest
	async def test006(self) -> None:
		await self.database.sendMessage(content='Test', channelID=1, userID=1)

	@asyncTest
	async def test007(self) -> None:
		await self.database.signUp(username='test1', password='testpassword', email='pie@gmail.com')
		await self.database.joinServer(userID=2, serverID=1)




if __name__ == '__main__':
	unittest.main()
