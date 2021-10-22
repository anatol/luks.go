package luks

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/anatol/devmapper.go"
)

// Volume represents information provided by an unsealed (i.e. with recovered password) LUKS slot
type Volume struct {
	backingDevice     string
	flags             []string // dmmapper flags
	uuid              string
	key               []byte
	luksType          string
	storageEncryption string
	storageIvTweak    uint64
	storageSectorSize uint64
	storageOffset     uint64 // offset of underlying storage in bytes
	storageSize       uint64 // length of underlying device in bytes, zero means that size should be calculated using `diskSize` function
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

	if v.storageSectorSize == 0 {
		return fmt.Errorf("invalid sector size")
	}
	if v.storageSectorSize != devmapper.SectorSize {
		kernelFlags = append(kernelFlags, "sector_size:"+strconv.Itoa(int(v.storageSectorSize)))
	}

	if v.storageSize%v.storageSectorSize != 0 {
		return fmt.Errorf("storage size must be multiple of sector size")
	}
	if v.storageOffset%v.storageSectorSize != 0 {
		return fmt.Errorf("offset must be multiple of sector size")
	}

	// the key should have hex format
	key := make([]byte, hex.EncodedLen(len(v.key)))
	hex.Encode(key, v.key)
	defer clearSlice(key)

	table := devmapper.CryptTable{
		StartSector:   0,
		Length:        v.storageSize / devmapper.SectorSize,
		BackendDevice: v.backingDevice,
		BackendOffset: v.storageOffset / devmapper.SectorSize,
		Encryption:    v.storageEncryption,
		Key:           string(key),
		IVTweak:       v.storageIvTweak,
		Flags:         kernelFlags,
	}

	uuid := fmt.Sprintf("CRYPT-%v-%v-%v", v.luksType, strings.ReplaceAll(v.uuid, "-", ""), name) // See dm_prepare_uuid()

	return devmapper.CreateAndLoad(name, uuid, 0, table)
}
