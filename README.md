## Burgernotes
Burgernotes is a simple note-taking app with end-to-end encryption.

### Setup
To set up Burgernotes, set it up like any other Fulgens Server module.
```
cd /path/to/fulgens/directory
git clone https://git.ailur.dev/ailur/burgernotes.git --depth=1 services-src/burgernotes
```
If you want to rebuild all of fulgens (recommended), run `./build.sh` in the fulgens directory.
If you only want to build the Burgernotes module, run `services-src/burgernotes/build.sh`.

### Configuration
Edit the main `config.json` file to include the Burgernotes module in the `services` object.
```json
{
    "burgernotes": {
        "subdomain": "notes.example.org",
        "hostName": "https://notes.example.org"
    }
}
```

### Running
Run the Fulgens server as you normally would.
```
./fulgens
```

### Links
[Go to the Burgernotes website](https://notes.ailur.dev)

[API documentation](APIDOCS.md)

[Roadmap](ROADMAP.md)
