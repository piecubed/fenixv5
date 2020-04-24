Messages
===============

sendMessage
~~~~~~~~~~~

::

    {
        'type': 'sendMessage',
        'channelID': int, 
        'contents': str
    }

-  If you dont have access to ``channelID``, then a
   `PermissionsError <#permissionserror>`__ is raised.
-  If contents is over 1000 characters, then a
   `ContentTooLong <#contenttoolong>`__ error is raised.

--------------

editMessage
~~~~~~~~~~~

::

    {
        'type': 'editMessage',
        'messageID': int,
        'contents': str
    }

-  If you aren't the owner of ``messageID``, then a
   `PermissionsError <#permissionserror>`__ is raised.
-  If contents is over 1000 characters, then a `ContentTooLong <#contenttoolong>`__ error is raised.
--------------

deleteMessage
~~~~~~~~~~~~~

::

    {
        'type': 'deleteMessage',
        'messageID': int
    }

-  If you don't have the `DeleteMessages <#deletemessagespermission>`__ permission, or if you didn't send the message, then a `PermissionsError <#permissionserror>`__ is raised.
--------------

addReaction
~~~~~~~~~~~

::

    {
        'type': 'addReaction',
        'messageID': int,
        'reaction': str
    }

-  If you don't have the `AddReaction <#addreactionpermission>`__
   permission, a `PermissionsError <#permissionserror>`__ is
   raised.
-  If ``reaction`` is not in the list of supported emojis, a `EmojiError <#emojierror>`__ is raised.
--------------

removeReaction
~~~~~~~~~~~~~~

::

    {
        'type': 'removeReaction',
        'messageID': int,
        'reaction': int
    }

-  ``reaction`` is the position of the emoji in the array of emojis
-  If you don't have the `DeleteMessages <#deletemessagespermission>`__
   permission, and you didn't send the message, a
   `PermissionsError <#permissionserror>`__ is raised.

--------------

Indices and tables
""""""""""""
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`