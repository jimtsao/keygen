package keygen

import (
	"bytes"
	"errors"
	"fmt"
	"math"
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
	// Charset specifies allowed printable characters (unicode categories L, M, N, P, S)
	//
	// Duplicate characters will occur in greater frequency
	Charset string
	// MinEntropy specifies minimum entropy in bits required for key
	MinEntropy uint16
	// KeyLength specifies number of characters in generated key
	// if this value is specified, minimum entropy value is ignored
	KeyLength uint16
}

// New returns a key generator with given config, or default values if nil
//
// Defaults to CharsetBase62 and 128 bit entropy
func New(c *Config) (*keygen, error) {
	k := &keygen{charset: CharsetBase62, minEntropy: 128}

	// default values
	if c == nil {
		return k, nil
	}

	// set config values
	if c.Charset != "" {
		// check charset is not empty or has single character
		if utf8.RuneCountInString(c.Charset) < 2 {
			return nil, errors.New("charset must contain more than 1 character")
		}

		// check for non printable unicode and duplicates
		for _, r := range c.Charset {
			if !unicode.IsPrint(r) || r == ' ' {
				return nil, fmt.Errorf("non printable unicode: '%U'", r)
			}
		}
		k.charset = c.Charset
	}

	// ignore entropy if keylength specified
	if c.KeyLength != 0 {
		k.keyLength = int(c.KeyLength)
	} else {
		k.minEntropy = int(c.MinEntropy)
	}

	return k, nil
}

func (k *keygen) Key() ([]byte, error) {
	// we calculate key length by dividing the minimum entropy needed
	// by the entropy of the charset specified, then rounding up
	charset := []rune(k.charset)
	charsetEntropy := int(math.Ceil(math.Log2(float64(len(charset)))))
	keyRuneCount := k.keyLength
	if keyRuneCount == 0 {
		// keylength not specified, we calculate from minimum entropy
		keyRuneCount = int(math.Ceil(float64(k.minEntropy) / float64(charsetEntropy)))
	}

	// determine max rune width
	maxRuneWidth := 1
	if k.charset != CharsetBase58 && k.charset != CharsetBase62 && k.charset != CharsetRFC6265 {
		for _, r := range charset {
			if maxRuneWidth == 4 {
				// utf-8 has max 4 bytes
				break
			}
			if l := utf8.RuneLen(r); l > maxRuneWidth {
				maxRuneWidth = l
			}
		}
	}

	// generate key
	var key bytes.Buffer
	key.Grow(keyRuneCount * maxRuneWidth)
	r := randgen{}
	for i := 0; i < keyRuneCount; {
		idx, err := r.randomBits(charsetEntropy)
		if err != nil {
			return nil, err
		}
		if idx < int64(len(charset)) {
			key.WriteRune(charset[idx])
			i++
		}
	}

	return key.Bytes(), nil
}
