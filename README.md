This is a Node module that provides auth token generation and management.
It has only been test with Express apps so far.

The tokens are encrypted strings that contain three pieces
of information: the username, the client IP address, and the
timestamp in milliseconds after which the session will expire.
The goal is to make it very difficult for a hacker to
impersonate a valid user or hijack an existing session.
Even if a hacker was able to intercept one of these tokens,
it would be difficult for them to utilize
because they would have to spoof the client IP address
and do that within the session timeout.

This module provides five functions.

## `configure`
This function must be called before any of the others.
It takes the name of an encryption algorithm,
a password to be used with it,
and a session timeout in minutes.
Encryption is provided by the builtin Node crypto module.
Supported encryption algorithms can be seen by running the following code:
```js
const crypto = require('crypto');
for (const cipher of crypto.getCiphers()) {
  console.log(cipher);
}
```
A recommended algorithm is "aes-256-ctr".

## `generateToken`
This function takes a username, request object,
and response object.  It creates an encrypted token
and returns it in the "Authorization" response header.
It also uses setTimeout to delete the token from its cache
after the session expires.
If `global.socket` is set, it assumes that is a reference
to a socket.io socket and emits a "session-timeout" event
rather than deleting the token from its cache.
This allows clients to proactively end a session rather than waiting
for the user to initiate a request that causes a new token check.

## `authorize`
This function takes a request and response object.
It extracts a token from the "Authorization" request header
and returns a boolean indicating whether the token matches
one that was created earlier using the `generateToken` function.
Any REST services that require authentication should call this
and exit if it returns false as shown below:
```js
if (!auth.authorize(req, res)) return;
```

## `deleteToken`
This function takes are request object and
deletes the token found in its "Authorization" request header
from the token cache.  This is useful when a user logs out
before their session expires.
It prevents future successful use of that token.

## `deleteExpiredTokens`
This function can be called at any time
to purge expired tokens from the cache.  This typically is
not necessary unless `global.socket` is set since otherwise
tokens are automatically deleted when their session expires.
