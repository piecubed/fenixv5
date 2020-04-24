Servers 
=======
--------------

createServer
~~~~~~~~~~~~

::

    {
        'type': 'createServer',
        'userID': int,
        'name': str,
    }

--------------

getServer
~~~~~~~~~

::

    {
        'type': 'getServer',
        'serverID': int,
    }

--------------

getServers
~~~~~~~~~~

::

    {
        'type': 'getServers',
        'serverID': int,
    }

--------------

getServersList
~~~~~~~~~~~~~~

::

    {
        'type': 'getServersList',
        'id': int,
    }

--------------

joinServer
~~~~~~~~~~

::

    {
        'type': 'joinServer',
        'userID': int,
        'serverID': int,
    }

Indices and tables
""""""""""""
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`