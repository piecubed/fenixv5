import unittest
from asyncTests import asyncTest
from fenix.database import Users, User

class UserDatabaseTests(unittest.TestCase):
    
    usersDatabase: Users = Users()
    
    async def createDatabase(self) -> None:
        with open('tables.psql', 'r') as f:
            await self.usersDatabase._execute(f.read())
    
    @asyncTest #type: ignore
    async def test2(self) -> None:
        await self.createDatabase()
        await self.usersDatabase.signUp('test', 'testpassword'.encode('utf-8'), 'piesquared@gmail.com')


if __name__ == '__main__':
    unittest.main()