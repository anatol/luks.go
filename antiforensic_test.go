package luks

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"testing"

	"golang.org/x/crypto/ripemd160"
)

func runAntiforensicTest(t *testing.T, hash hash.Hash) {
	t.Parallel()

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

func TestAntiforensicSha256(t *testing.T) {
	runAntiforensicTest(t, sha256.New())
}

func TestAntiforensicRipemd160(t *testing.T) {
	runAntiforensicTest(t, ripemd160.New())
}
