package keygen

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

// randgen encapsulates underlying optimisation to giving out random bits
type randgen struct {
	cache  uint64
	cursor int
}

// randomBits gives up to maximum 18 cryptographically random bits
func (r *randgen) randomBits(n int) int {
	// as randomBits is used to generate an index to choose
	// a character from a given character set, given the total
	// number of printable unicode characters we allow is 143,571
	// the maximum we can expect is 18 bits, i.e. 2^18, which covers
	// 262,144 characters
	if n <= 0 || n > 18 {
		panic("invalid random bits requested")
	}

	// refresh cache if needed
	if r.cache == 0 || r.cursor+n > 63 {
		r.refreshCache()
	}

	// fetch bits from cache
	bits := (r.cache >> r.cursor) & ((1 << n) - 1)
	r.cursor += n

	// can safely convert uint64 to int, as int returned is never
	// expected to exceed number of printable unicode characters
	// i.e. 143,571, which is less than 2^31
	return int(bits)
}

// refreshCache generates new random bits and stores in cache
func (r *randgen) refreshCache() {
	var buf [8]byte
	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		panic(err)
	}
	r.cache = binary.LittleEndian.Uint64(buf[:])
	r.cursor = 0
}
