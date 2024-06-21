# 🍔 Burgernotes API docs
Use the Burgernotes API to automate tasks, build your own client, and more!

Headers should be: "Content-type: application/json; charset=UTF-8" for all POSTs

## 🔑 Authentication

POST - /api/signup - provide "username" and "password".

POST - /api/login - provide "username", "password"

To prevent the server from knowing the encryption key, the password you provide in the request must be hashed with the SHA-3 algorithm with 128 iterations (the hash is hashed again 128 times).

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

POST - /api/removenote - remove notes, provide "secretKey" and "noteId"

## ⚙️ More stuff

POST - /api/deleteaccount - delete account, provide "secretKey"
please display a warning before this action

POST - /api/exportnotes - export notes, provide "secretKey"
note content and title will have to be decrypted

POST - /api/sessions/list - show all sessions, provide "secretKey"

POST - /api/sessions/remove - remove session, provide "secretKey" and "sessionId"

POST - /api/listusers - lists all users in JSON, provide "masterKey" (set in config.ini)
