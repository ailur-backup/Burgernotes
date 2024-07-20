# 🍔 Burgernotes API docs
Use the Burgernotes API to automate tasks, build your own client, and more!

Headers should be: "Content-type: application/json; charset=UTF-8" for all POSTs

## 🔑 Authentication

POST - /api/signup - provide "username" and "password".

POST - /api/login - provide "username" and "password"

To prevent the server from knowing the encryption key, the password you provide in the request must be hashed with Argon2ID as per the following parameters:
 
- salt: UTF-8 Representation of "I munch Burgers!!" (should be 16 bytes),
- parallelism: 1
- iterations: 32
- memorySize: 19264 bytes
- hashLength: 32
- outputType: hexadecimal

Password should be at least 8 characters, username must be under 20 characters and alphanumeric.

If username is taken, error code 422 will return.

Assuming everything went correctly, the server will return a secret key.

You'll need to store two things in local storage:
- The secret key you just got, used to fetch notes, save stuff etc.
- Another password, which is hashed the same way, but with a salt of "I love Burgernotes!" (again, UTF-8 representation, 16 bytes).

If you are using the OAuth2 flow (totally optional, I know it's really complex) then you should also store the login password to use later, or put the OAuth2 logic straight after this.

## 🌐 OAuth2 + Burgerauth

For security purposes, traditional OAuth2 is not supported. Instead, we use Burgerauth, a custom OAuth2 implementation that provides a unique-yet-consistent "authentication code" for each user. It is created in a special way as to not involve the server, meaning the security of Burgernotes is not compromised by using OAuth2, which is normally a very server-side process.

### How it works
First, perform regular client-side OAuth2 authentication using Burgerauth, as detailed in its [own documentation](https://concord.hectabit.org/HectaBit/burgerauth/src/branch/main/APIDOCS.md). Once regular OAuth2 is complete, you will be given an authentication code, which is important for the next step.

You now have one of two options:
1. If your app is based on the web, you can host a static page provided [here](https://concord.hectabit.org/HectaBit/burgerauth/src/branch/main/keyExchangeRdir.html) on any static service. Redirect to this page with the OAuth2 token stored in localStorage as BURGERAUTH-RDIR-TOKEN. The page will then communicate with a corresponding page on Burgerauth, and transmit the key securely via RSA. You may see the page redirect a couple of times as it communicates the infomation across. All you need to know is that once it is finished, it will redirect back to the page that redirected to it with the key in localStorage as DONOTSHARE-EXCHANGED-KEY.
2. If your app is not web-based, you can open up a webview to [here](https://auth.hectabit.org/keyexchangeclient). Once it is finished, it will send a postMessage with the body "finished" to the target "*" and output "finished" to the JavaScript console. The key will be in localStorage as DONOTSHARE-EXCHANGED-KEY.
3. Alternatively, you can host a local webserver and host the aforementioned page on it. It will work the same way as the first option, and once it is finished, it will detect that it was not redirected to and instead will set it as a cookie expiring in 5 minutes and then refresh the page. You should detect for the cookie and use its value, and then kill the webserver. This method is not recommended because of its complexity and overhead.

Once this is finished, you should check if there is an existing OAuth2 entry on the server like this:

POST - /api/oauth/get - provide "username" and "oauthProvider"
oauthProvider is the name of the OAuth2 provider, such as "burgerauth" or "google" (google is used as an example, they do not use the burgerauth extensions and are therefore incompatible).
It does not have to be the actual name, but it has to be unique to the provider (per user). The sub given by OpenID Connect is a good choice.

### 404 is returned
No entry has been found, and you have to log in the user as normal.
Once this is done, you should create an entry like this:

POST - /api/oauth/new - provide "secretKey", "oauthProvider" and "encryptedPassword"

To create encryptedPassword, follow these steps:

1. Generate a random 16-byte IV.
2. Create a JSON structure like this: 
```json
{
    "loginPass": "(the SHA-3 password hash created in the login process)",
    "cryptoPass": "(the SHA-512 password hash stored in localStorage)"
}
```
3. Convert the JSON to a string and then encrypt it using AES-256 GCM using the exchangeKey as the key and the IV created earlier as the IV.
4. Create a JSON structure like this:
```json
{
    "iv": "(the IV)",
    "content": "(the encrypted JSON)"
}
```
5. Finally, convert the JSON into a string, base64 encode it, and send it off as encryptedPassword.

Do not store the exchangeKey after this point, as it is no longer needed.

### 200 is returned
An entry exists, and encryptedPassword has been returned using JSON.
encryptedPassword is the password encrypted using AES-256 GCM, and the IV is included in the JSON, in this format defined above.

Use the passwords defined in the JSON structure before the last one to log in normally.

#### Finally, you are done!

## 🔐 Encryption

Note content and title is encrypted using AES 256-bit.

Encryption password is the SHA512 hashed password we talked about earlier.

## 🕹️ Basic stuff

POST - /api/userinfo - get user info such as username, provide "secretKey"

POST - /api/listnotes - list notes, provide "secretKey"
note titles will have to be decrypted.

POST - /api/newnote - create a note, provide "secretKey" and "noteName"
"noteName" should be encrypted using AES-256 GCM with the DONOTSHARE-password as the key and a random 16-byte IV.

POST - /api/readnote - read notes, provide "secretKey" and "noteId"
note content will have to be decrypted.

POST - /api/editnote - edit notes, provide "secretKey", "noteId", "title", and "content"
"content" should be encrypted using AES-256 GCM with the DONOTSHARE-password as the key and a random 16-byte IV.
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
note content and title should be encrypted using AES-256 GCM with the DONOTSHARE-password as the key and a random 16-byte IV and follow the /api/exportnotes format, in a marshalled json string

POST - /api/sessions/list - show all sessions, provide "secretKey"

POST - /api/sessions/remove - remove session, provide "secretKey" and "sessionId"

## ‍💼 Admin controls

POST - /api/listusers - lists all users in JSON, provide "masterKey" (set in config.ini)
