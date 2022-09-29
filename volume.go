package luks

import (
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

	uuid := fmt.Sprintf("CRYPT-%v-%v-%v", v.LuksType, strings.ReplaceAll(v.UUID, "-", ""), name) // See dm_prepare_uuid()

	return devmapper.CreateAndLoad(name, uuid, 0, table)
}
