package luks

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// error that indicates provided passphrase does not match
var ErrPassphraseDoesNotMatch = fmt.Errorf("Passphrase does not match")

type Device interface {
	io.Closer
	// Version returns version of LUKS disk
	Version() int
	// Path returns block device path
	Path() string
	// Uuid returns UUID of the LUKS partition
	Uuid() string
	// Slots returns list of all active slots for this device sorted by priority
	Slots() []int
	// Slots returns list of available tokens (metadata) for slots
	Tokens() ([]Token, error)
	Unlock(keyslot int, passphrase []byte, dmName string) error
	UnlockAny(passphrase []byte, dmName string) error
}

type TokenType int

const (
	UnknownTokenType TokenType = iota
	ClevisTokenType
)

type Token struct {
	Slots   []int
	Type    TokenType
	Payload []byte
}

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
	controlFile, err := os.Open("/dev/mapper/control")
	if err != nil {
		return err
	}
	defer controlFile.Close()

	return dmIoctl(controlFile, unix.DM_DEV_REMOVE, name, "", nil)
}
