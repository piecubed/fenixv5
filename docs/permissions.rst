Permissions
===========


--------------

changeServerPermission
~~~~~~~~~~~~~~~~~~~~~~

::

    {
        'type': 'changeServerPermission',
        'permission': str,
        'value': bool,
        'userID': int,
        'serverID': int,
    }

--------------

changechannelPermission
~~~~~~~~~~~~~~~~~~~~~~~

::

    {
        'type': 'changechannelPermission',
        'permission': str,
        'value': bool,
        'userID': int,
        'channelID': int,
    }

-------------

getPerms
~~~~~~~~

::

    {
        'type': 'getPerms',
        'userID': int,
        'serverID': int,
    }

--------------

getPermsList
~~~~~~~~~~~~

::

    {
        'type': 'getPermsList',
        'userID': int,
        'serverID': int,
    }

--------------

hasChannelPermission
~~~~~~~~~~~~~~~~~~~~

::

    {
        'type': 'hasChannelPermission',
        'permission': str,
        'userID': int,
        'channelID': int,
    }

--------------

hasServerPermission
~~~~~~~~~~~~~~~~~~~

::

    {
        'type': 'hasServerPermission',
        'permission': str,
        'userID': int,
        'serverID': int,
    }

Indices and tables
""""""""""""
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`