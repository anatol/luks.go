package luks

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/anatol/devmapper.go"
)

// ErrPassphraseDoesNotMatch is an error that indicates provided passphrase does not match
var ErrPassphraseDoesNotMatch = fmt.Errorf("Passphrase does not match")

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

// Open reads LUKS headers from the given partition and returns LUKS device object.
// This function internally handles LUKS v1 and v2 partitions metadata.
func Open(path string) (Device, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// LUKS Magic and version are stored in the first 8 bytes of the LUKS header
	header := make([]byte, 8)
	if _, err := f.ReadAt(header[:], 0); err != nil {
		return nil, err
	}

	// verify header magic
	if !bytes.Equal(header[0:6], []byte("LUKS\xba\xbe")) {
		return nil, fmt.Errorf("invalid LUKS header")
	}

	version := int(header[6])<<8 + int(header[7])
	switch version {
	case 1:
		return initV1Device(path, f)
	case 2:
		return initV2Device(path, f)
	default:
		return nil, fmt.Errorf("invalid LUKS version %v", version)
	}
}

// Lock closes device mapper partition with the given name
func Lock(name string) error {
	return devmapper.Remove(name)
}
