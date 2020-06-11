# Fenix
![Test](https://github.com/piecubed/fenix/workflows/Test/badge.svg)  
Fenix is a communication standard, designed for ease of use, and an excellent user expierience.

----------
## Connecting
Fenix uses [websockets](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API) to communicate to the Fenix server.  Currently, fenix doesn't have a stable endpoint, if you have interest in developing a client for fenix, open an issue, and ill move it to a permanent endpoint.

## Authenticating
Fenix uses HTTP headers to authenticate users.
The method of authentication depends on the path the websocket is on.
### Token
At `/token`

Needs a `Token` header.

### SignIn
At `/signIn`

Needs `Email` and `Password` headers.

### SignUp
At `/signUp`

Needs `Email`, `Password`, and `Username` headers.

In the prerelease version of the app, there is no Google ReCaptcha verification, when that is added again, an additional `Response` header is required, with the response token you will get from google.

## Packets
All packets on fenix are JSON encoded, and have an required `type` field, and a required `id` field, which is echoed back from the server on whatever response it has.

### TODO Add a list of packets
For now, just look in fenix/protocol.py.  I reccomend using that, and _protocolCore for any python fenix client, since all the packets are nicely registered.
