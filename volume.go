package luks

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha1"   // register crypto.SHA1 for HMAC
	_ "crypto/sha256" // register crypto.SHA256
	_ "crypto/sha512" // register crypto.SHA384 and crypto.SHA512
	"fmt"
	"strings"

	"github.com/anatol/devmapper.go"
)

// Volume represents information provided by an unsealed (i.e. with recovered password) LUKS slot
type Volume struct {
	BackingDevice     string
	Flags             []string // luks-named flags
	UUID              string
	key               []byte // keep decoded key field private for security reasons
	LuksType          string
	StorageEncryption string
	StorageIvTweak    uint64
	StorageSectorSize uint64
	StorageOffset     uint64 // offset of underlying storage in bytes
	StorageSize       uint64 // length of underlying device in bytes, zero means that size should be calculated using `diskSize` function
}

// map of LUKS flag names to its dm-crypt counterparts
var flagsKernelNames = map[string]string{
	FlagAllowDiscards:       devmapper.CryptFlagAllowDiscards,
	FlagSameCPUCrypt:        devmapper.CryptFlagSameCPUCrypt,
	FlagSubmitFromCryptCPUs: devmapper.CryptFlagSubmitFromCryptCPUs,
	FlagNoReadWorkqueue:     devmapper.CryptFlagNoReadWorkqueue,
	FlagNoWriteWorkqueue:    devmapper.CryptFlagNoWriteWorkqueue,
}

// hmacAllowedHashes restricts HMAC to standard-library hash implementations.
// The hash is selected by a crypto.Hash identifier rather than a caller-supplied
// constructor, so callers cannot inject an implementation that observes the
// volume key during the HMAC computation.
var hmacAllowedHashes = map[crypto.Hash]bool{
	crypto.SHA1:   true,
	crypto.SHA256: true,
	crypto.SHA384: true,
	crypto.SHA512: true,
}

// HMAC returns HMAC(volume key, message) using the given hash. The hash is
// identified by a crypto.Hash value and must be one of the supported algorithms;
// the volume key is only ever fed to a trusted standard-library implementation.
// It never leaves the package — callers receive only the resulting digest, which
// carries no key material. This lets a consumer bind a value to the unlocked
// volume (e.g. measure it into a TPM PCR) without the master key crossing the
// package boundary.
func (v *Volume) HMAC(h crypto.Hash, message []byte) ([]byte, error) {
	if !hmacAllowedHashes[h] {
		return nil, fmt.Errorf("luks: HMAC: unsupported hash %s", h)
	}
	if !h.Available() {
		return nil, fmt.Errorf("luks: HMAC: hash %s is not available", h)
	}
	mac := hmac.New(h.New, v.key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

// SetupMapper creates a device mapper for the given LUKS volume
func (v *Volume) SetupMapper(name string) error {
	kernelFlags := make([]string, 0, len(v.Flags))
	for _, f := range v.Flags {
		flag, ok := flagsKernelNames[f]
		if !ok {
			return fmt.Errorf("unknown LUKS flag: %v", f)
		}
		kernelFlags = append(kernelFlags, flag)
	}

	// dm-crypt requires both size and offset to be aligned to the sector size
	if v.StorageSize%v.StorageSectorSize != 0 {
		return fmt.Errorf("storage size must be multiple of sector size")
	}
	if v.StorageOffset%v.StorageSectorSize != 0 {
		return fmt.Errorf("offset must be multiple of sector size")
	}

	table := devmapper.CryptTable{
		Start:         0,
		Length:        v.StorageSize,
		BackendDevice: v.BackingDevice,
		BackendOffset: v.StorageOffset,
		Encryption:    v.StorageEncryption,
		Key:           v.key,
		IVTweak:       v.StorageIvTweak,
		Flags:         kernelFlags,
		SectorSize:    v.StorageSectorSize,
	}

	// Build a UUID in the format expected by cryptsetup's dm_prepare_uuid():
	// "CRYPT-<type>-<uuid_no_dashes>-<dm_name>"
	uuid := fmt.Sprintf("CRYPT-%v-%v-%v", v.LuksType, strings.ReplaceAll(v.UUID, "-", ""), name)

	return devmapper.CreateAndLoad(name, uuid, 0, table)
}
