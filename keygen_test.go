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

	key, err := k.Key()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// default key length should be 22 characters
	if len(key) != 22 {
		t.Logf("expected key length %d, got %d", 22, len(key))
		t.Fail()
	}
}

func TestNewBadConfig(t *testing.T) {
	confs := []struct {
		Error      string
		Charset    string
		MinEntropy int
		KeyLength  int
	}{
		{"empty charset", "", 128, 0},
		{"charset must contain more than 1 character", "a", 128, 0},
		{"non printable unicode: 'U+0020'", "a b", 128, 0},
		{"non printable unicode: 'U+2002'", "a\u2002b", 128, 0},
		{"duplicate character: 'b'", "abbc", 128, 0},
		{"minimum entropy must be > 0", keygen.CharsetBase62, 0, 0},
		{"minimum entropy must be > 0", keygen.CharsetBase62, -1, 0},
		{"key length must be >= 0", keygen.CharsetBase62, 128, -1},
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
		MinEntropy int
		KeyLength  int
		TestFn     func(string)
	}{
		// test charset unicode support
		{"日本", 128, 0, func(key string) {
			for _, char := range key {
				if char != '日' && char != '本' {
					t.Logf("expected charset '日本', got character: '%#q'", char)
					t.Fail()
					break
				}
			}
		}},

		// test min entropy
		{"12345678", 128, 0, func(key string) {
			// charset has 3 bit entropy, 128 / 3 = 42.66
			if len(key) != 43 {
				t.Logf("expected minimum entropy: %d, got: %d", 128, 3*len(key))
				t.Fail()
			}
		}},

		// test key length overrides minimum entropy
		{keygen.CharsetBase62, 128, 3, func(key string) {
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
		key, err := k.Key()
		if err != nil {
			t.Error(err)
			continue
		}
		test.TestFn(key)
	}
}
