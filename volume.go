package luks

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha1"   // register crypto.SHA1 for HMAC
	_ "crypto/sha256" // register crypto.SHA256
	_ "crypto/sha512" // register crypto.SHA384 and crypto.SHA512
	"fmt"
	"os"
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

	// TCG OPAL hardware-encryption segments (cryptsetup >= 2.7). For these,
	// key holds the full digest-verified keyslot key: its first opalKeySize
	// bytes are the OPAL locking-range passphrase, the remainder (empty for
	// "hw-opal") is the dm-crypt volume key.
	segmentType       string // "" or "crypt" (dm-crypt), "hw-opal", "hw-opal-crypt"
	opalKeySize       uint64
	opalSegmentNumber uint
	opalSegmentSize   uint64 // locking-range length in bytes
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
	switch v.segmentType {
	case "", "crypt": // "" covers LUKS1, which predates segment types
		return v.setupCryptMapper(name)
	case "hw-opal", "hw-opal-crypt":
		return v.setupOpalMapper(name)
	default:
		return fmt.Errorf("unsupported segment type: %v", v.segmentType)
	}
}

// dmUUID builds a UUID in the format expected by cryptsetup's
// dm_prepare_uuid(): "CRYPT-<type>-<uuid_no_dashes>-<dm_name>"
func (v *Volume) dmUUID(name string) string {
	return fmt.Sprintf("CRYPT-%v-%v-%v", v.LuksType, strings.ReplaceAll(v.UUID, "-", ""), name)
}

// Clear wipes the volume key material. Call it once the volume is no longer
// needed (after SetupMapper); the Unlock/UnlockAny helpers do this
// automatically.
func (v *Volume) Clear() {
	clearSlice(v.key)
}

// kernelFlags translates the LUKS-named flags to their dm-crypt counterparts,
// erroring on flags this library does not know.
func (v *Volume) kernelFlags() ([]string, error) {
	flags := make([]string, 0, len(v.Flags))
	for _, f := range v.Flags {
		flag, ok := flagsKernelNames[f]
		if !ok {
			return nil, fmt.Errorf("unknown LUKS flag: %v", f)
		}
		flags = append(flags, flag)
	}
	return flags, nil
}

// buildCryptTable assembles the dm-crypt table shared by the software and the
// hw-opal-crypt activation paths; key is the dm-crypt volume key.
func (v *Volume) buildCryptTable(key []byte) (*devmapper.CryptTable, error) {
	kernelFlags, err := v.kernelFlags()
	if err != nil {
		return nil, err
	}

	// dm-crypt requires both size and offset to be aligned to the sector size
	if v.StorageSize%v.StorageSectorSize != 0 {
		return nil, fmt.Errorf("storage size must be multiple of sector size")
	}
	if v.StorageOffset%v.StorageSectorSize != 0 {
		return nil, fmt.Errorf("offset must be multiple of sector size")
	}

	return &devmapper.CryptTable{
		Start:         0,
		Length:        v.StorageSize,
		BackendDevice: v.BackingDevice,
		BackendOffset: v.StorageOffset,
		Encryption:    v.StorageEncryption,
		Key:           key,
		IVTweak:       v.StorageIvTweak,
		Flags:         kernelFlags,
		SectorSize:    v.StorageSectorSize,
	}, nil
}

func (v *Volume) setupCryptMapper(name string) error {
	table, err := v.buildCryptTable(v.key)
	if err != nil {
		return err
	}
	return devmapper.CreateAndLoad(name, v.dmUUID(name), 0, *table)
}

// setupOpalMapper activates a TCG OPAL hardware-encrypted segment: it unlocks
// the drive's locking range with the OPAL prefix of the keyslot key, then maps
// the now-readable range with dm-linear ("hw-opal") or dm-crypt on top of it
// ("hw-opal-crypt").
func (v *Volume) setupOpalMapper(name string) error {
	if v.opalKeySize == 0 || v.opalKeySize > uint64(len(v.key)) {
		return fmt.Errorf("invalid OPAL key size %d for a %d-byte volume key", v.opalKeySize, len(v.key))
	}
	opalKey := v.key[:v.opalKeySize]

	// Validate header flags even where dm-linear later drops them: an
	// unknown flag means a header this library does not fully understand.
	if _, err := v.kernelFlags(); err != nil {
		return err
	}

	// SED ioctls work on the partition fd; the kernel routes them to the
	// controller. Read-only is sufficient for all of them.
	f, err := os.Open(v.BackingDevice)
	if err != nil {
		return err
	}
	defer f.Close()

	status, err := opalGetStatusIoctl(f)
	if err != nil {
		return err
	}
	const needed = opalFlSupported | opalFlLockingSupported
	if status.Flags&needed != needed {
		return fmt.Errorf("device %v does not support OPAL locking (status flags %#x)", v.BackingDevice, status.Flags)
	}

	// Before unlocking, verify that the locking range the drive reports
	// matches the geometry the LUKS2 header promises: a divergence would
	// expose the wrong ciphertext as if it were the volume. Only when the
	// firmware genuinely cannot answer the queries (ENOTTY/EOPNOTSUPP) is
	// the verification skipped; any other failure — notably NOT_AUTHORIZED —
	// is fatal. When skipping, the range is conservatively treated as
	// having been locked, so a later failure re-locks it; the flip side
	// (re-locking a range that was already unlocked, possibly in use
	// elsewhere) is accepted as the lesser risk.
	wasLocked := true
	geo, err := opalGetGeometryIoctl(f)
	switch {
	case err == nil:
		lr, err := opalGetLrStatusIoctl(f, v.opalSegmentNumber, opalKey)
		switch {
		case err == nil:
			partStart, err := partitionStartSector(f)
			if err != nil {
				return err
			}
			if err := verifyOpalGeometry(lr, geo.LogicalBlockSize, partStart, v.StorageOffset, v.opalSegmentSize); err != nil {
				return err
			}
			wasLocked = lr.LState == opalLK
		case isOpalQueryUnsupported(err):
			// verification skipped, see above
		default:
			return err
		}
	case isOpalQueryUnsupported(err):
		// verification skipped, see above
	default:
		return err
	}

	if err := opalUnlock(f, v.opalSegmentNumber, opalKey); err != nil {
		return err
	}
	// A save failure only affects resume from S3 suspend (the range comes
	// back locked); re-locking stays functional because relockOnError
	// passes the key explicitly.
	_ = opalSaveUnlockForResume(f, v.opalSegmentNumber, opalKey)

	var table devmapper.Table
	if v.segmentType == "hw-opal" {
		// no software encryption: the unlocked range is plaintext
		table = devmapper.LinearTable{
			Start:         0,
			Length:        v.StorageSize,
			BackendDevice: v.BackingDevice,
			BackendOffset: v.StorageOffset,
		}
	} else {
		cryptTable, err := v.buildCryptTable(v.key[v.opalKeySize:])
		if err != nil {
			return v.relockOnError(f, wasLocked, opalKey, err)
		}
		table = *cryptTable
	}

	if err := devmapper.CreateAndLoad(name, v.dmUUID(name), 0, table); err != nil {
		return v.relockOnError(f, wasLocked, opalKey, err)
	}
	return nil
}

// relockOnError restores the locked state after a post-unlock failure, but
// only when the range was actually locked when we found it. The key is passed
// explicitly so re-locking works even when the save step failed and the
// kernel has no stored copy.
func (v *Volume) relockOnError(f *os.File, wasLocked bool, opalKey []byte, err error) error {
	if !wasLocked {
		return err
	}
	if lockErr := opalLock(f, v.opalSegmentNumber, opalKey); lockErr != nil {
		return fmt.Errorf("%w (additionally, re-locking the OPAL range failed: %v)", err, lockErr)
	}
	return err
}
