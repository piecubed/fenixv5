import unittest
from asyncTests import asyncTest
from fenix.database import Database, User, Server

class UserDatabaseTests(unittest.TestCase):
    
    database: Database = Database()
    async def createDatabase(self) -> None:
        with open('tables.psql', 'r') as f:
            await self.database._execute(f.read())
    
    @asyncTest #type: ignore
    async def test1(self) -> None:
        await self.createDatabase()
        await self.database.signUp('test', 'testpassword', 'piesquared@gmail.com')
    
    @asyncTest #type: ignore
    async def test2(self) -> None:
        await self.database.fetchUserByEmail('piesquared@gmail.com')
    
    @asyncTest #type: ignore
    async def test3(self) -> None:
        self.user = await self.database.signIn('piesquared@gmail.com', 'testpassword')
    
    @asyncTest #type: ignore
    async def test4(self) -> None:
        await self.serversDatabase.createServer('1', 'Test')
    
    @asyncTest #type: ignore
    async def test5(self) -> None:
        await self.database.joinServer('1', '1')
        await self.createDatabase()
        
if __name__ == '__main__':
    unittest.main()