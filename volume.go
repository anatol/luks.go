package luks

import (
	"fmt"
	"strings"

	"github.com/anatol/devmapper.go"
)

// Volume represents information provided by an unsealed (i.e. with recovered password) LUKS slot
type Volume struct {
	backingDevice     string
	flags             []string // luks-named flags
	uuid              string
	key               []byte
	luksType          string
	storageEncryption string
	storageIvTweak    uint64
	storageSectorSize uint64
	storageOffset     uint64 // offset of underlying storage in bytes
	storageSize       uint64 // length of underlying device in bytes, zero means that size should be calculated using `diskSize` function
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
	kernelFlags := make([]string, 0, len(v.flags))
	for _, f := range v.flags {
		flag, ok := flagsKernelNames[f]
		if !ok {
			return fmt.Errorf("unknown LUKS flag: %v", f)
		}
		kernelFlags = append(kernelFlags, flag)
	}

	if v.storageSize%v.storageSectorSize != 0 {
		return fmt.Errorf("storage size must be multiple of sector size")
	}
	if v.storageOffset%v.storageSectorSize != 0 {
		return fmt.Errorf("offset must be multiple of sector size")
	}

	table := devmapper.CryptTable{
		Start:         0,
		Length:        v.storageSize,
		BackendDevice: v.backingDevice,
		BackendOffset: v.storageOffset,
		Encryption:    v.storageEncryption,
		Key:           v.key,
		IVTweak:       v.storageIvTweak,
		Flags:         kernelFlags,
		SectorSize:    v.storageSectorSize,
	}

	uuid := fmt.Sprintf("CRYPT-%v-%v-%v", v.luksType, strings.ReplaceAll(v.uuid, "-", ""), name) // See dm_prepare_uuid()

	return devmapper.CreateAndLoad(name, uuid, 0, table)
}
