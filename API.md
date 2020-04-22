# Fenixv5 API

Fenix uses websockets, and the current endpoint is `wss://bloblet.com:3300`.

All methods will accept an `id` parameter, which will be returned without changes.  This is optional, but it's nicely useful to make sure you are handling the same request you made.

## General Template

```
{
    'id': optional,
    'type': str,
    ...
}
```

## Permissions

At the time of writing, fenix has the following server permissions:
```
admin
addChannels
assignRoles
kick
ban
changeNick
changeOthersNick
```
and these channel permissions:
```
canRead
canTalk
canReadHistory
canDeleteMessages
canManageChannel
canManagePermissions
canPinMessages
canPingEveryone
```

Not going to actually document all of these, but server permissions need `userID` (int), `serverID` (int), and `value` (bool) fields.

## Creating a server
