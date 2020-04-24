Welcome to fenix!
=======================================================

Fenixv5 API
===========

Fenix uses websockets, and the current endpoint is
``wss://bloblet.com:3300``.

All methods will accept an ``id`` parameter, which will be returned
without changes. This is optional, but it's nicely useful to make sure
you are handling the same request you made.

General Template
~~~~~~~~~~~

::

    {
        'id': optional,
        'type': str,
        ...
    }

----------------------------------------------------------------------------------------------------------------------


.. toctree::
   :maxdepth: 2

   auth.rst
   channel.rst
   messages.rst
   permissions.rst
   role.rst
   server.rst
   
   
Indices and tables
^^^^^^^^^^^^^^^^
* :ref:`contents`
* :ref:`search`
