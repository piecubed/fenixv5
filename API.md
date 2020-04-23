![yay](https://cdn.discordapp.com/attachments/675016140879167523/675177177980862465/f_squircle.png)
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

## Message related

### sendMessage

```
{
    'type': 'sendMessage',
    'channelID': int, 
    'contents': str
}
```

- If you dont have access to `channelID`, then a [_`PermissionsError`_](#permissionserror) is raised.  
- If contents is over 1000 characters, then a [_`ContentTooLong`_](#contenttoolong) error is raised.

---
### editMessage
```
{
    'type': 'editMessage',
    'messageID': int,
    'contents': str
}
```

- If you aren't the owner of `messageID`, then a [_`PermissionsError`_](#permissionserror) is raised.  
- If contents is over 1000 characters, then a [_`ContentTooLong`_](#contenttoolong) error is raised.
---
### deleteMessage
```
{
    'type': 'deleteMessage',
    'messageID': int
}
```
- If you don't have the [DeleteMessages](#deletemessagespermission) permission, or if you didn't send the message, then a [_`PermissionsError`_](#permissionserror) is raised.  
---

### addReaction
```
{
    'type': 'addReaction',
    'messageID': int,
    'reaction': str
}
```
- If you don't have the [AddReaction](#addreactionpermission) permission, a [_`PermissionsError`_](#permissionserror) is raised.
- If `reaction` is not in the list of supported emojis, a [_`EmojiError`_](#emojierror) is raised.
---
### removeReaction
```
{
    'type': 'removeReaction',
    'messageID': int,
    'reaction': int
}
```
- `reaction` is the position of the emoji in the array of emojis
- If you don't have the [DeleteMessages](#deletemessagespermission) permission, and you didn't send the message, a [_`PermissionsError`_](#permissionserror) is raised.

---
## Channel related
### channelHistory
```
{
    'type': 'channelHistory',
    'channelID': int,
    'lastMessage': int
}
```
- `lastMessage` is the last message you recieved in `channelID`
- You will recive the most recent 50 (or less) new messages in `channelID` in array format.
- If you can't read `channelID` or can't read its history, a [_`PermissionsError`_](#permissionserror) is raised.
---
### 