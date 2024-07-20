DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS oauth;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    migrated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator INTEGER NOT NULL,
    created TEXT NOT NULL,
    edited TEXT NOT NULL,
    content TEXT NOT NULL,
    title TEXT NOT NULL
);

CREATE TABLE oauth (
    id INTEGER NOT NULL,
    oauthProvider TEXT NOT NULL,
    encryptedPasswd TEXT NOT NULL,
    UNIQUE (id, oauthProvider)
)