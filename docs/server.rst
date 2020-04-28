Servers
=======
--------------

createServer
~~~~~~~~~~~~

::

    {
        'type': 'createServer',
        'name': str,
    }

Creates a server, `name`, and sends back a `server <#server>`__

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
        'serverID': int,
    }

--------------

joinServer
~~~~~~~~~~

::

    {
        'type': 'joinServer',
        'serverID': int,
    }

Indices and tables
""""""""""""
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`