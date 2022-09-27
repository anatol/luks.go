package luks

import (
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"

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
	require.NoError(t, err)
	require.Len(t, dest, 64*4000)

	final, err := afMerge(dest, keySize, stripes, hash)
	require.NoError(t, err)

	require.Equal(t, secret, final)
}

func TestAntiforensicSha256(t *testing.T) {
	runAntiforensicTest(t, sha256.New())
}

func TestAntiforensicRipemd160(t *testing.T) {
	runAntiforensicTest(t, ripemd160.New())
}
