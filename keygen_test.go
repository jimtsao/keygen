package keygen_test

import (
	"testing"

	"github.com/jimtsao/keygen"
)

func TestNewDefault(t *testing.T) {
	k, err := keygen.New(nil)
	// nil config should always return nil error
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	key := k.Key()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// default key length should be 22 characters
	if len(key) != 22 {
		t.Logf("expected key length %d, got %d", 22, len(key))
		t.Fail()
	}

	// key shouldn't be all 0s
	if string(key) == "0000000000000000000000" {
		t.Logf("key empty: %s", key)
		t.Fail()
	}
}

func TestNewBadConfig(t *testing.T) {
	confs := []struct {
		Error      string
		Charset    string
		MinEntropy uint16
		KeyLength  uint16
	}{
		{"charset must contain more than 1 character", "a", 128, 0},
		{"non printable unicode: 'U+0020'", "a b", 128, 0},
		{"non printable unicode: 'U+2002'", "a\u2002b", 128, 0},
	}

	for _, conf := range confs {
		_, err := keygen.New(&keygen.Config{
			Charset:    conf.Charset,
			MinEntropy: conf.MinEntropy,
			KeyLength:  conf.KeyLength,
		})
		if err == nil || err.Error() != conf.Error {
			t.Logf("expected: %s, got: %s", conf.Error, err)
			t.Fail()
		}
	}
}

func TestNewGoodConfig(t *testing.T) {
	tests := []struct {
		Charset    string
		MinEntropy uint16
		KeyLength  uint16
		TestFn     func([]byte)
	}{
		// test charset unicode support
		{"日本", 128, 0, func(key []byte) {
			for _, r := range string(key) {
				if r != '日' && r != '本' {
					t.Logf("expected charset '日本', got character: '%#q'", r)
					t.Fail()
					break
				}
			}
		}},

		// test min entropy
		{"12345678", 128, 0, func(key []byte) {
			// charset has 3 bit entropy, 128 / 3 = 42.66
			if len(key) != 43 {
				t.Logf("expected minimum entropy: %d, got: %d", 128, 3*len(key))
				t.Fail()
			}
		}},

		// test key length overrides minimum entropy
		{keygen.CharsetBase62, 128, 3, func(key []byte) {
			if len(key) != 3 {
				t.Logf("expected key length: %d, got: %d", 22, len(key))
				t.Fail()
			}
		}},
	}

	for _, test := range tests {
		conf := &keygen.Config{
			Charset:    test.Charset,
			MinEntropy: test.MinEntropy,
			KeyLength:  test.KeyLength,
		}
		k, err := keygen.New(conf)
		if err != nil {
			t.Error(err)
			continue
		}
		key := k.Key()
		test.TestFn(key)
	}
}
