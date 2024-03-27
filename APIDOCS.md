# 🍔 Burgernotes API docs
Use the Burgernotes API to automate tasks, build your own client, and more!

Headers should be: "Content-type: application/json; charset=UTF-8" for all POSTs

## 🔑 Authentication

POST - /api/signup - provide "username" and "password".

POST - /api/login - provide "username", "password", "passwordchange" (must be "yes" or "no") and "newpass"

To prevent the server from knowing the encryption key, the password you provide in the request must be hashed with the SHA-3 with 128 iterations (the hash is hashed again 128 times).

If you wish to change the user's password, set "passwordchange" to "yes" and "newpass" to the new hash.


Some users use the legacy argon2id mode (by which i mean about 8, so only implement if you feel like it), and to implement argon2id functionality, you hash like this:
```
Parallelism should be 1

Iterations should be 256

Memory Allocated in bytes should be 512

Length of Hash should be 32 bytes

The output should be in the encoded format, not the hashed format

Salt should be the SHA512 of the password
```

(Yes i know this is really bad practice, guess why we are replacing it)

To test if SHA-3 or argon2 is used, just try the SHA-3 and if 422 gets returned try argon2.

(For the sake of all of us, change the password to the SHA-3 hash)


Password should be at least 8 characters, username must be under 20 characters and alphanumeric.

If username is taken, error code 422 will return.

Assuming everything went correctly, the server will return a secret key.

You'll need to store two things in local storage:
- The secret key you just got, used to fetch notes, save stuff etc.
- A SHA512 hashed password, used as encryption key

## 🔐 Encryption

Note content and title is encrypted using AES 256-bit.

Encryption password is the SHA512 hashed password we talked about earlier.

## 🕹️ Basic stuff

POST - /api/userinfo - get user info such as username, provide "secretKey"

POST - /api/listnotes - list notes, provide "secretKey"
note titles will have to be decrypted.

POST - /api/newnote - create a note, provide "secretKey" and "noteName"
"noteName" should be encrypted.

POST - /api/readnote - read notes, provide "secretKey" and "noteId"
note content will have to be decrypted.

POST - /api/editnote - edit notes, provide "secretKey", "noteId", "title", and "content"
"content" should be encrypted.
"title" is the first line of the note content, and should be encrypted.

**(Deprecated ⚠️)** POST - /api/editnotetitle - edit note titles, provide "secretKey", "noteId", and "content"
"content" should be encrypted.

POST - /api/removenote - remove notes, provide "secretKey" and "noteId"

## ⚙️ More stuff

POST - /api/deleteaccount - delete account, provide "secretKey"
please display a warning before this action

POST - /api/exportnotes - export notes, provide "secretKey"
note content and title will have to be decrypted

POST - /api/sessions/list - show all sessions, provide "secretKey"

POST - /api/sessions/remove - remove session, provide "secretKey" and "sessionId"
