import unittest
from asyncTests import asyncTest
from fenix.database import Users, User

class UserDatabaseTests(unittest.TestCase):
    
    usersDatabase: Users = Users()
    
    @asyncTest #type: ignore
    async def test1(self) -> None:
        await self.usersDatabase.signUp('test', 'testpassword'.encode('utf-8'), 'test@test.test')
        
    @asyncTest #type: ignore
    async def test2(self) -> None:
        print('Test2') 
    
    @asyncTest #type: ignore
    async def test3(self) -> None:
        print('Test3')
    
    @asyncTest #type: ignore
    async def test4(self) -> None:
        print('Test4') 

if __name__ == '__main__':
    unittest.main()