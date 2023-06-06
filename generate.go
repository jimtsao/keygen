package keygen

import (
	"bytes"
	"math"
	"unicode/utf8"
)

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
