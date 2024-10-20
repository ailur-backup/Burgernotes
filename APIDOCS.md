# API documentation

The Burgernotes API is a RESTful API that allows you to interact with the Burgernotes service. The API is designed to be simple and easy to use.
It uses Protocol Buffers for serialization and deserialization, and POST requests for all operations.

## Protobuf types
These are some basic Protobuf types that are used in the API.
All protocol buffers are using proto3 syntax.
```protobuf
syntax = "proto3";

// Token is a string that represents an OAuth2 JWT token.
message Token {
  string token = 1;
}

// NoteID is a UUID that represents a note.
message NoteID {
  bytes noteId = 1;
}

// NoteID and Token together represent a request involving a note.
message NoteRequest {
  NoteID noteId = 1;
  Token token = 2;
}

// AESData represents AES-encrypted data.
message AESData {
  bytes data = 2;
  bytes iv = 3;
}

// NoteMetadata represents the metadata of a note.
message NoteMetadata {
  NoteID noteId = 1;
  AESData title = 2;
}

// Note represents a note.
message Note {
  NoteMetadata metadata = 1;
  AESData note = 2;
}

// Invitation represents an invitation to a note.
message Invitation {
  string username = 1;
  AESData key = 2;
  NoteID noteId = 3;
}

// User represents a user editing notes.
message UserLines {
  string username = 1;
  bytes uuid = 2;
  repeated uint64 lines = 3;
}

// Error represents an error.
message Error {
  string error = 1;
}

// ServerError represents a 500 error, with a hex error code.
message ServerError {
  bytes errorCode = 1;
}
```
## Errors
In any response, if an error occurs, it will return an `Error` or `ServerError` message.
### 400 Range
```protobuf
message Error {
  string error = 1;
}
```
The error is formatted to be human-readable, you may display it to the user.
### HTTP 500
```protobuf
message ServerError {
    bytes errorCode = 1;
}
```
ServerError is a hex byte which represents the error code. You should give a vague error message to the user.

## Authentication
### /api/signup - POST
#### Request
```protobuf
message ApiSignupRequest {
    bytes publicKey = 1;
    Token token = 2;
}
```
#### Response
200 OK
No response body

### /api/delete - POST - Show a warning before this action!
#### Request
```protobuf
message Token {
  string token = 1;
}
```
#### Response
HTTP 200 OK
No response body

## Interacting with notes
### /api/notes/add - POST
#### Request
```protobuf
message Token {
  string token = 1;
}
```
#### Response
HTTP 200 OK
```protobuf
message NoteID {
  bytes noteId = 1;
}
```

### /api/notes/remove - POST
#### Request
```protobuf
message NoteRequest {
  NoteID noteId = 1;
  Token token
}
```
#### Response
HTTP 200 OK
No response body

### /api/notes/list - POST
#### Request
```protobuf
message Token {
  string token = 1;
}
```
#### Response
HTTP 200 OK
```protobuf
message ApiNotesListResponse {
    repeated NoteMetadata notes = 1;
}
```

### /api/notes/get - POST
#### Request
```protobuf
message NoteRequest {
  NoteID noteId = 1;
  Token token
}
```
#### Response
HTTP 200 OK
```protobuf
message Note {
  NoteMetadata metadata = 1;
  AESData note = 2;
}
```

### /api/notes/edit - POST
#### Request
```protobuf
message ApiNotesEditRequest {
    Note note = 1;
    Token token = 2;
}
```
#### Response
HTTP 200 OK
No response body

### /api/notes/purge - POST - Show a warning before this action!
#### Request
```protobuf
message Token {
  string token = 1;
}
```
#### Response
HTTP 200 OK
No response body

## Shared notes - This is not yet implemented
### /api/invite/prepare - POST
#### Request
```protobuf
message ApiInvitePrepareRequest {
    string username = 1;
    Token token = 2;
}
```
#### Response
HTTP 200 OK
```protobuf
message ApiInvitePrepareResponse {
    bytes ecdhExchange = 1;
}
```

### /api/invite/check - POST
#### Request
```protobuf
message Token {
    string token = 1;
}
```
#### Response
HTTP 200 OK
```protobuf
message ApiInviteCheckResponse {
    repeated Invitation invitations = 1;
}
```

### /api/invite/link - POST
#### Request
```protobuf
message ApiInviteLinkRequest {
    NoteRequest noteRequest = 1;
    int64 timestamp = 2;
    bool singleUse = 3;
}
```
#### Response
HTTP 200 OK
```protobuf
message ApiInviteLinkResponse {
    bytes inviteCode = 1;
}
```

### /api/invite/accept - POST
#### Request
```protobuf
message ApiInviteAcceptRequest {
    bytes inviteCode = 1;
    Token token = 2;
}
```
#### Response
HTTP 200 OK
```protobuf
message NoteID {
    bytes noteId = 1;
}
```

### /api/invite/leave - POST
#### Request
```protobuf
message NoteRequest {
    NoteID noteId = 1;
    Token token
}
```
#### Response
HTTP 200 OK
No response body

### /api/shared - WebSocket
Every heartbeat interval (500ms):
#### Request
```protobuf
message ApiSharedRequest {
    repeated uint64 lines = 1;
    Token token = 2;
}
```
#### Response
```protobuf
message ApiSharedResponse {
    repeated UserLines users = 1;
}
```

### /api/shared/edit - POST
#### Request
```protobuf
message ApiSharedEditRequest {
    repeated AESData lines = 1;
    Token token = 2;
}
```
#### Response
HTTP 200 OK
No response body

### /api/shared/get - POST
#### Request
```protobuf
message NoteRequest {
    NoteID noteId = 1;
    Token token
}
```
#### Response
```protobuf
message ApiSharedGetResponse {
    repeated AESData lines = 1;
    NoteMetadata metadata = 2;
}
```