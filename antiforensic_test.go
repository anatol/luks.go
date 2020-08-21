package luks

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestAntiforensic(t *testing.T) {
	hash := sha256.New()
	stripes := 4000
	password := []byte("my password")
	keySize := 64

	secret := make([]byte, keySize)
	secret = append(secret, password...)
	secret = secret[:keySize] // expand input data to its key size

	dest, err := afSplit(secret, stripes, hash)
	if err != nil {
		t.Fatal(err)
	}

	if len(dest) != 64*4000 {
		t.Fatal()
	}

	final, err := afMerge(dest, keySize, stripes, hash)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secret, final) {
		t.Fatal()
	}
}
