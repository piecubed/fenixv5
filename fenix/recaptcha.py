from aiohttp import client
import json
import datetime


class RECaptcha:
    _endpoint = 'https://www.google.com/recaptcha/api/siteverify'

    async def verify(self, resToken: str) -> bool:
        async with client.ClientSession() as c:
            async with c.post(self._endpoint, data=json.dumps({'secret': 'YaySecret!', 'response': resToken})) as res:
                body = await res.json()
                return body['success'] and (datetime.datetime.now() - datetime.datetime.fromisoformat(body['challenge_ts'])).seconds <= 10
