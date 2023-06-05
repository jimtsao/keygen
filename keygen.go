package keygen

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// CharsetBase58 alphanumeric minus ambiguous characters 0, I, O and L
const CharsetBase58 = "123456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// CharsetBase62 alphanumeric characters, good for human readable keys
const CharsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// CharsetRFC6265 conforms to RFC6265, good for cookie values
const CharsetRFC6265 = CharsetBase62 + "!#$%&'()*+-./:<=>?@[]^_`{|}~"

type keygen struct {
	charset    string
	minEntropy int
	keyLength  int
}

type Config struct {
	// Charset specifies allowed characters. Must be subset of [0-9][a-z][A-Z]
	Charset string
	// MinEntropy specifies minimum entropy in bits required for key
	MinEntropy int
	// KeyLength specifies number of characters in generated key, if this
	// value is > 0, minimum entropy value is ignored
	KeyLength int
}

// New returns a key generator with given config, or default values if nil
//
// If no config is specified, error is always nil
func New(c *Config) (*keygen, error) {
	// default values
	k := &keygen{}
	if c == nil {
		k.charset = CharsetBase62
		k.minEntropy = 128
		return k, nil
	}

	// custom values
	// -- check charset is not empty or has single character
	if c.Charset == "" {
		return nil, errors.New("empty charset")
	} else if utf8.RuneCountInString(c.Charset) == 1 {
		return nil, errors.New("charset must contain more than 1 character")
	}
	dups := map[rune]bool{}
	// -- check for non printable unicode and duplicates
	for _, r := range c.Charset {
		if !unicode.IsPrint(r) || r == ' ' {
			return nil, fmt.Errorf("non printable unicode: '%U'", r)
		}

		if dups[r] {
			return nil, fmt.Errorf("duplicate character: %q", r)
		} else {
			dups[r] = true
		}
	}
	k.charset = c.Charset

	// user specified either key length or minimum entropy
	if c.KeyLength != 0 {
		// -- check key length
		if c.KeyLength < 0 {
			return nil, errors.New("key length must be >= 0")
		}
		k.keyLength = c.KeyLength
	} else {
		// -- check minimum entropy
		if c.MinEntropy < 1 {
			return nil, errors.New("minimum entropy must be > 0")
		}
		k.minEntropy = c.MinEntropy
	}

	return k, nil
}
