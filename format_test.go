package luks

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTempDisk creates a temporary file of size bytes, suitable for use as a LUKS device.
func newTempDisk(t *testing.T, size int64) *os.File {
	t.Helper()
	f, err := os.CreateTemp("", "luks.go.format.disk")
	require.NoError(t, err)
	require.NoError(t, f.Truncate(size))
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f
}

// cryptsetupIsLuks verifies that cryptsetup recognises the file as a valid LUKS device.
func cryptsetupIsLuks(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command("cryptsetup", "isLuks", path)
	require.NoError(t, cmd.Run(), "cryptsetup isLuks failed — file is not a valid LUKS device")
}

// cryptsetupLuksDump runs cryptsetup luksDump and returns its stdout+stderr output.
func cryptsetupLuksDump(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command("cryptsetup", "luksDump", path)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "cryptsetup luksDump failed:\n%s", string(out))
}

// -------------------------------------------------------------------------
// FormatV1 self-tests
// -------------------------------------------------------------------------

func TestFormatV1Basic(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 4*1024*1024)
	defer disk.Close()

	passphrase := []byte("hunter2")
	dev, err := FormatV1(disk.Name(), passphrase, &FormatV1Options{Iter: 100})
	require.NoError(t, err)
	defer dev.Close()

	require.Equal(t, 1, dev.Version())
	require.Equal(t, []int{0}, dev.Slots())

	_, err = dev.UnsealVolume(0, passphrase)
	require.NoError(t, err)

	_, err = dev.UnsealVolume(0, []byte("wrong"))
	require.ErrorIs(t, err, ErrPassphraseDoesNotMatch)
}

func TestFormatV1CustomOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts FormatV1Options
	}{
		{"sha256", FormatV1Options{Hash: "sha256", Iter: 100}},
		{"sha512", FormatV1Options{Hash: "sha512", Iter: 100}},
		{"sha1", FormatV1Options{Hash: "sha1", Iter: 100}},
		{"key64", FormatV1Options{MasterKeySize: 64, Iter: 100}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			disk := newTempDisk(t, 4*1024*1024)
			defer disk.Close()

			opts := tc.opts
			dev, err := FormatV1(disk.Name(), []byte("pass"), &opts)
			require.NoError(t, err)
			defer dev.Close()

			_, err = dev.UnsealVolume(0, []byte("pass"))
			require.NoError(t, err)
		})
	}
}

func TestFormatV1UUID(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 4*1024*1024)
	defer disk.Close()

	wantUUID := "12345678-1234-4234-a234-123456789abc"
	dev, err := FormatV1(disk.Name(), []byte("pass"), &FormatV1Options{
		UUID: wantUUID,
		Iter: 100,
	})
	require.NoError(t, err)
	defer dev.Close()

	require.Equal(t, wantUUID, dev.UUID())
}

// -------------------------------------------------------------------------
// FormatV2 self-tests
// -------------------------------------------------------------------------

func TestFormatV2Basic(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 32*1024*1024)
	defer disk.Close()

	passphrase := []byte("hunter2")
	dev, err := FormatV2(disk.Name(), passphrase, &FormatV2Options{
		KDFType: "pbkdf2",
		KDFIter: 100,
	})
	require.NoError(t, err)
	defer dev.Close()

	require.Equal(t, 2, dev.Version())
	require.Equal(t, []int{0}, dev.Slots())

	_, err = dev.UnsealVolume(0, passphrase)
	require.NoError(t, err)

	_, err = dev.UnsealVolume(0, []byte("wrong"))
	require.ErrorIs(t, err, ErrPassphraseDoesNotMatch)
}

func TestFormatV2UUID(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 32*1024*1024)
	defer disk.Close()

	wantUUID := "12345678-1234-4234-a234-123456789abc"
	dev, err := FormatV2(disk.Name(), []byte("pass"), &FormatV2Options{
		UUID:    wantUUID,
		KDFType: "pbkdf2",
		KDFIter: 100,
	})
	require.NoError(t, err)
	defer dev.Close()

	require.Equal(t, wantUUID, dev.UUID())
}

func TestFormatV2KDFVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts FormatV2Options
	}{
		{
			"pbkdf2",
			FormatV2Options{KDFType: "pbkdf2", KDFIter: 100, KDFHash: "sha256"},
		},
		{
			"pbkdf2-sha512",
			FormatV2Options{KDFType: "pbkdf2", KDFIter: 100, KDFHash: "sha512"},
		},
		{
			"argon2i",
			FormatV2Options{KDFType: "argon2i", KDFTime: 1, KDFMemory: 32768, KDFCPUs: 1},
		},
		{
			"argon2id",
			FormatV2Options{KDFType: "argon2id", KDFTime: 1, KDFMemory: 32768, KDFCPUs: 1},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			disk := newTempDisk(t, 32*1024*1024)
			defer disk.Close()

			opts := tc.opts
			dev, err := FormatV2(disk.Name(), []byte("testpass"), &opts)
			require.NoError(t, err)
			defer dev.Close()

			_, err = dev.UnsealVolume(0, []byte("testpass"))
			require.NoError(t, err)
		})
	}
}

func TestFormatV2SectorSize(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 32*1024*1024)
	defer disk.Close()

	dev, err := FormatV2(disk.Name(), []byte("pass"), &FormatV2Options{
		KDFType:    "pbkdf2",
		KDFIter:    100,
		SectorSize: 4096,
	})
	require.NoError(t, err)
	defer dev.Close()

	v, err := dev.UnsealVolume(0, []byte("pass"))
	require.NoError(t, err)
	require.Equal(t, uint64(4096), v.StorageSectorSize)
}

// -------------------------------------------------------------------------
// FormatV1 interoperability: our format → cryptsetup verify
// -------------------------------------------------------------------------

func TestFormatV1Interop_OurFormatCryptsetupReads(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 4*1024*1024)
	defer disk.Close()

	dev, err := FormatV1(disk.Name(), []byte("interop1"), &FormatV1Options{Iter: 1000})
	require.NoError(t, err)
	dev.Close()

	cryptsetupIsLuks(t, disk.Name())
	cryptsetupLuksDump(t, disk.Name())

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)

	dev2, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev2.Close()
	require.Equal(t, uuid, dev2.UUID())
}

// -------------------------------------------------------------------------
// FormatV2 interoperability: our format → cryptsetup verify
// -------------------------------------------------------------------------

func TestFormatV2Interop_OurFormatCryptsetupReads(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 32*1024*1024)
	defer disk.Close()

	dev, err := FormatV2(disk.Name(), []byte("interop2"), &FormatV2Options{
		KDFType: "pbkdf2",
		KDFIter: 1000,
	})
	require.NoError(t, err)
	dev.Close()

	cryptsetupIsLuks(t, disk.Name())
	cryptsetupLuksDump(t, disk.Name())

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)

	dev2, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev2.Close()
	require.Equal(t, uuid, dev2.UUID())
}
