package keygen

import (
	"errors"
	"fmt"
)

const defaultCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type keygen struct {
	charset    string
	minEntropy int
	checksum   bool
}

type Config struct {
	// Charset specifies allowed characters. Must be subset of [0-9][a-z][A-Z]
	Charset    string
	MinEntropy int
	Checksum   bool
}

// New returns a key generator with given config, or default values if nil
func New(cfg *Config) (*keygen, error) {
	// default values
	if cfg == nil {
		k := &keygen{charset: defaultCharset, minEntropy: 128, checksum: true}
		return k, nil
	}

	// custom values
	// -- check charset
	if cfg.Charset == "" {
		return nil, fmt.Errorf("empty charset")
	}
	dups := map[rune]bool{}
	for _, r := range cfg.Charset {
		// check rune within allowed character set
		if !('0' <= r && r <= '9') && !('a' <= r && r <= 'z') && !('A' <= r && r <= 'Z') {
			return nil, fmt.Errorf("invalid character: %q", r)
		}

		// check for duplicate characters
		if dups[r] {
			return nil, fmt.Errorf("duplicate character: %q", r)
		} else {
			dups[r] = true
		}
	}
	// -- check minimum entropy
	if cfg.MinEntropy < 1 {
		return nil, errors.New("minimum entropy must be > 0")
	}

	k := &keygen{
		charset:    cfg.Charset,
		minEntropy: cfg.MinEntropy,
		checksum:   cfg.Checksum,
	}

	return k, nil
}
