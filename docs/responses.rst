Responses
=======
--------------

server
~~~~~~~~~~~~

::

    {
        'type': 'server',
        'serverID': int,
        'name': str,
        'users': List[Dict]
    }

``users`` is a dict, containing somthing like
::
    {
        <user ID, int>: {
            'avatar': str,
            'name': str
        },
    }

with ``name`` being the nickname of the user in that server, if more is needed about the user, see `getUserByID <#getuserbyid>`__

--------------

authUser
~~~~~~~~~~~~

::

    {
        'type': 'user',
        'userID': int,
        'nick': str,
        'servers': List[Dict],
        'token': str,
        'email': str
    }

a full user object with auth info

--------------

authUser
~~~~~~~~~~~~

::

    {
        'type': 'user',
        'userID': int,
        'nick': str,
        'servers': List[Dict],
        'token': str,
        'email': str
    }

--------------

channel
~~~~~~~~~~~~

::

    {
        'type': 'channel',
        'channelID': int,
        'nick': str,
        'servers': List[Dict],
        'token': str,
        'email': str
    }
