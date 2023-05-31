# keygen

Generates cryptographically random keys that can be used as session ids, api keys or authentication tokens etc. Generated keys support:

- multiple charsets (Base58, Base62, RFC6265 cookie compatible or custom unicode compatible charset)
- minimum entropy, or
- key length (number of characters)

You can also override the following parameters:

- character set (default: `[a-z][A-Z][0-9]`)
- minimum entropy (default: 128 bits)
- key length (default: 0)

## Installation

`go get https://github.com/justasable/keygen`

## Example Usage

Using Default Values

```go
k, err := keygen.New(nil)
key, err := k.Key()
```

Using Config

```go
k, err := keygen.New(&keygen.Config{
    Charset: keygen.CharsetRFC6265,
    MinEntropy: 256,
})
key, err := k.Key()
```

Setting Custom Charset and Key Length

```go
k, err := keygen.New(&keygen.Config{
    Charset: "日本語",
    KeyLength: 10,
})
key, err := k.Key()
```
