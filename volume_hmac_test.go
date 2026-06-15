package luks

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVolumeHMAC verifies Volume.HMAC computes HMAC(volume key, message) with
// the requested standard-library hash, without exposing the key. Consumers
// (e.g. booster's PCR15 latch) use this to bind a value to the unlocked volume —
// the digest is the only thing that leaves the package.
func TestVolumeHMAC(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	v := &Volume{key: key}
	msg := []byte("cryptsetup:cryptroot:5cbc48ce-0e78-4c6b-ac90-a8a540514b90")

	got256, err := v.HMAC(crypto.SHA256, msg)
	require.NoError(t, err)
	want256 := hmac.New(sha256.New, key)
	want256.Write(msg)
	require.Equal(t, want256.Sum(nil), got256, "HMAC-SHA256")

	got1, err := v.HMAC(crypto.SHA1, msg)
	require.NoError(t, err)
	want1 := hmac.New(sha1.New, key)
	want1.Write(msg)
	require.Equal(t, want1.Sum(nil), got1, "HMAC-SHA1 (per-bank hash)")
}

// TestVolumeHMACRejectsUnsupportedHash ensures a hash outside the allowlist is
// refused rather than used — callers cannot smuggle in an untrusted algorithm.
func TestVolumeHMACRejectsUnsupportedHash(t *testing.T) {
	v := &Volume{key: []byte("0123456789abcdef0123456789abcdef")}
	_, err := v.HMAC(crypto.MD5, []byte("x"))
	require.Error(t, err)
}
