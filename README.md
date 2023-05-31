# keygen

Generates cryptographically random keys that can be used as session ids, api keys or authentication tokens etc. Generated keys support:

- multiple charsets (Base58, Base62, RFC6265 or custom unicode compatible charset)
- minimum entropy, or
- key length (number of characters)

You can also override the following parameters:

- character set (default: `[a-z][A-Z][0-9]`)
- minimum entropy (default: 128 bits)
- key length (default: 0)

## Installation

`go get https://github.com/justasable/keygen`
