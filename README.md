# keygen

Generates cryptographically random keys that can be used as session ids, api keys or authentication tokens etc. Keys are:

- cryptographically random
- human readable (base62)

You can also override the following parameters:

- character set (default: `[a-z][A-Z][0-9]`)
- minimum entropy (default: 128 bits)

## Installation

`go get https://github.com/justasable/keygen`
