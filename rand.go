package keygen

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// randgen encapsulates underlying optimisation to giving out random bits
type randgen struct {
	cache  uint64
	cursor int
}

// randomBits gives up to maximum 64 cryptographically random bits
func (r *randgen) randomBits(n int) (int64, error) {
	// range check
	if n > 64 {
		return 0, errors.New("n must be between 0 and 64 inclusive")
	}

	// refresh cache if needed
	if r.cache == 0 || r.cursor+n > 63 {
		if err := r.refreshCache(); err != nil {
			return 0, err
		}
	}

	// fetch bits from cache
	bits := (r.cache >> r.cursor) & ((1 << n) - 1)
	r.cursor += n

	return int64(bits), nil
}

// refreshCache generates new random bits and stores in cache
func (r *randgen) refreshCache() error {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	r.cache = binary.LittleEndian.Uint64(b)
	r.cursor = 0
	return nil
}
