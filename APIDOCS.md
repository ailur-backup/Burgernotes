# 🍔 Burgernotes API docs
Use the Burgernotes API to automate tasks, build your own client, and more!

Headers should be: "Content-type: application/json; charset=UTF-8" for all POSTs

## 🔑 Authentication (version 1)

POST - /api/signup - provide "username" and "password".

POST - /api/login - provide "username", "password" and "newpass"

To prevent the server from knowing the encryption key, the password you provide in the request must be hashed with the SHA-3 algorithm with 128 iterations (the hash is hashed again 128 times).

Password should be at least 8 characters, username must be under 20 characters and alphanumeric.

Newpass is a more direct call to /api/changepassword that is deprecated in version 2. Set newpass to a value of "no" in order to identify as a version 1 api and not trigger the backwards compatibility layer.

If username is taken, error code 422 will return.

Assuming everything went correctly, the server will return a secret key.

You'll need to store two things in local storage:
- The secret key you just got, used to fetch notes, save stuff etc.
- A SHA512 hashed password, used as encryption key

### Additional notes on version 2

For version two, /api/signup and /api/login require the legacyPassword API, to allow for backwards compatibility up to version 0. To do this, set the header "X-Burgernotes-Version" to the current version number without any dots (E.G 2.1.4 -> 214). 

During signup, "legacyPassword" should also be provided. legacyPassword should be the SHA-3 128 iteration hash of the Argon2ID hash of the password following these settings (yes, hashing a hash):

```
Parallelism should be 1

Iterations should be 256

Memory Allocated in bytes should be 512

Length of Hash should be 32 bytes

The output should be in the encoded format, not the hashed format

Salt should be the SHA512 of the password
```

On login, as well as the key, the server may return "legacyPasswordNeeded" = true.

If this is the case, POST /api/v2/addlegacypassword (with the aforementioned header), provide "secretKey" and "legacyPassword" (hashed the same way as signup).

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

POST - /api/removenote - remove notes, provide "secretKey" and "noteId"

POST - /api/purgenotes - remove all notes, provide "secretKey"
### Please display a warning before this action

## ⚙️ Account management

POST - /api/changepassword - change account password, provide "secretKey", "newPassword"
encrypt the same way as /api/login

POST - /api/deleteaccount - delete account, provide "secretKey"
### Please display a warning before this action

POST - /api/exportnotes - export notes, provide "secretKey"
note content and title will have to be decrypted

POST - /api/importnotes - import notes, provide "secretKey" and "notes"
note content should be encrypted and follow the /api/exportnotes format, in a marshalled json string

POST - /api/sessions/list - show all sessions, provide "secretKey"

POST - /api/sessions/remove - remove session, provide "secretKey" and "sessionId"

## ‍💼 Admin controls

POST - /api/listusers - lists all users in JSON, provide "masterKey" (set in config.ini)
