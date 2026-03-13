package luks

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/anatol/devmapper.go"
)

// ErrPassphraseDoesNotMatch is an error that indicates provided passphrase does not match
var ErrPassphraseDoesNotMatch = errors.New("passphrase does not match")

// ErrNotSupported is returned when an operation is not supported by the LUKS version.
var ErrNotSupported = errors.New("operation not supported")

// FormatV1Options holds configuration for creating a new LUKS v1 device.
// Zero values for numeric fields mean "use default".
type FormatV1Options struct {
	// UUID is used as the partition UUID; auto-generated when empty.
	UUID string
	// Cipher name (default "aes").
	Cipher string
	// CipherMode is the cipher mode (default "xts-plain64").
	CipherMode string
	// Hash algorithm used for PBKDF2 and AF diffusion (default "sha256").
	Hash string
	// MasterKeySize is the volume key size in bytes (default 32, i.e. 256-bit key).
	// For AES-XTS the value covers both sub-keys: 32 → AES-128-XTS, 64 → AES-256-XTS.
	MasterKeySize int
	// Iter is the PBKDF2 iteration count for the first keyslot.
	// When 0, a value is derived from IterTime.
	Iter int
	// IterTime is the target key-derivation time in milliseconds (default 2000).
	// Only used when Iter == 0.
	IterTime int
}

// FormatV2Options holds configuration for creating a new LUKS v2 device.
// Zero values for numeric fields mean "use default".
type FormatV2Options struct {
	// UUID is used as the partition UUID; auto-generated when empty.
	UUID string
	// Label is an optional human-readable device label.
	Label string
	// Cipher name (default "aes").
	Cipher string
	// CipherMode is the cipher mode (default "xts-plain64").
	CipherMode string
	// SectorSize is the logical sector size in bytes (default 512).
	SectorSize int
	// MasterKeySize is the volume key size in bytes (default 64, i.e. 512-bit key).
	MasterKeySize int
	// KDFType selects the key-derivation function: "argon2id", "argon2i", or "pbkdf2"
	// (default "argon2id").
	KDFType string
	// KDFHash is the hash algorithm used by the KDF and digest (default "sha256").
	KDFHash string
	// KDFIter is the PBKDF2 iteration count (only used when KDFType == "pbkdf2").
	KDFIter int
	// KDFTime is the Argon2 time cost parameter (default 4).
	KDFTime uint32
	// KDFMemory is the Argon2 memory cost in KiB (default 1048576 = 1 GiB).
	KDFMemory uint32
	// KDFCPUs is the Argon2 parallelism parameter (default 4).
	KDFCPUs uint8
}

// Device represents LUKS partition data
type Device interface {
	io.Closer
	// Version returns version of LUKS disk
	Version() int
	// Path returns block device path
	Path() string
	// UUID returns UUID of the LUKS partition
	UUID() string
	// Slots returns list of all active slots for this device sorted by priority
	Slots() []int
	// Tokens returns list of available tokens (metadata) for slots
	Tokens() ([]Token, error)
	// FlagsGet get the list of LUKS flags (options) used during unlocking
	FlagsGet() []string
	// FlagsAdd adds LUKS flags used for the upcoming unlocking
	// Note that this method does not update LUKS v2 persistent flags
	FlagsAdd(flags ...string) error
	// FlagsClear clears flags
	// Note that this method does not update LUKS v2 persistent flags
	FlagsClear()

	// UnsealVolume recovers slot password and then populates Volume structure that contains information needed to
	// create a mapper device
	UnsealVolume(keyslot int, passphrase []byte) (*Volume, error)

	// Unlock is a shortcut for
	// ```go
	//   volume, err := dev.UnsealVolume(keyslot, passphrase)
	//   volume.SetupMapper(dmName)
	// ```
	Unlock(keyslot int, passphrase []byte, dmName string) error
	// UnlockAny iterates over all available slots and tries to unlock them until succeeds
	UnlockAny(passphrase []byte, dmName string) error

	// AddKey adds a new keyslot encrypted with newPassphrase.
	// existingPassphrase must match any active keyslot to prove authority.
	// Returns the new keyslot ID.
	AddKey(existingPassphrase, newPassphrase []byte) (int, error)

	// AddKeyToSlot is like AddKey but places the new key into the specified slot.
	AddKeyToSlot(slot int, existingPassphrase, newPassphrase []byte) error

	// KillSlot wipes keyslot slot. passphrase must match a *different* active
	// keyslot so that access to the volume is not lost.
	KillSlot(slot int, passphrase []byte) error

	// RemoveKey finds and wipes the first keyslot whose passphrase matches.
	RemoveKey(passphrase []byte) error

	// ChangeKey replaces the passphrase of whichever slot matches existingPassphrase.
	ChangeKey(existingPassphrase, newPassphrase []byte) error

	// HeaderBackup writes a complete backup of the LUKS header region to path.
	HeaderBackup(path string) error

	// HeaderRestore replaces the on-disk LUKS header with the contents of path.
	// WARNING: any key material not present in the backup file is permanently lost.
	HeaderRestore(path string) error

	// AddToken adds a LUKS v2 JSON token and returns the new token ID.
	// Returns an error on LUKS v1 devices.
	AddToken(t Token) (int, error)

	// RemoveToken deletes the LUKS v2 token with the given ID.
	// Returns an error on LUKS v1 devices.
	RemoveToken(id int) error
}

// List of options handled by luks.go API.
// These names correspond to LUKSv2 persistent flags names (see persistent_flags[] array).
const (
	FlagAllowDiscards       string = "allow-discards"
	FlagSameCPUCrypt        string = "same-cpu-crypt"
	FlagSubmitFromCryptCPUs string = "submit-from-crypt-cpus"
	FlagNoReadWorkqueue     string = "no-read-workqueue"  // supported at Linux 5.9 or newer
	FlagNoWriteWorkqueue    string = "no-write-workqueue" // supported at Linux 5.9 or newer
)

// Token represents LUKS token metadata information
type Token struct {
	ID    int
	Slots []int
	// Type of the token e.g. "clevis", "systemd-fido2"
	Type    string
	Payload []byte
}

// openFromFiles detects the LUKS version from hdrF, verifies the magic bytes,
// and dispatches to the appropriate init function.
func openFromFiles(devicePath string, hdrF, dataF *os.File) (Device, error) {
	// LUKS magic and version are stored in the first 8 bytes of the LUKS header
	header := make([]byte, 8)
	if _, err := hdrF.ReadAt(header, 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[0:6], []byte("LUKS\xba\xbe")) {
		return nil, fmt.Errorf("invalid LUKS header")
	}
	version := int(header[6])<<8 + int(header[7])
	switch version {
	case 1:
		return initV1Device(devicePath, hdrF, dataF)
	case 2:
		return initV2Device(devicePath, hdrF, dataF)
	default:
		return nil, fmt.Errorf("invalid LUKS version %d", version)
	}
}

// Open reads LUKS headers from the given partition and returns LUKS device object.
// This function internally handles LUKS v1 and v2 partitions metadata.
func Open(path string) (Device, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	dev, err := openFromFiles(path, f, f)
	if err != nil {
		f.Close()
	}
	return dev, err
}

// OpenWithHeader opens a LUKS device that uses a detached header.
// The LUKS metadata and keyslot material are read from headerPath,
// while the encrypted data resides on devicePath.
func OpenWithHeader(devicePath, headerPath string) (Device, error) {
	hdrF, err := os.Open(headerPath)
	if err != nil {
		return nil, err
	}
	dataF, err := os.Open(devicePath)
	if err != nil {
		hdrF.Close()
		return nil, err
	}
	dev, err := openFromFiles(devicePath, hdrF, dataF)
	if err != nil {
		hdrF.Close()
		dataF.Close()
	}
	return dev, err
}

// Lock closes device mapper partition with the given name
func Lock(name string) error {
	return devmapper.Remove(name)
}
