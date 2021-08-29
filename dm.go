package luks

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/anatol/devmapper.go"
)

func createDmDevice(path string, dmName string, partitionUUID string, volume *volumeInfo, flags []string) error {
	uuid := fmt.Sprintf("CRYPT-%v-%v-%v", volume.luksType, strings.ReplaceAll(partitionUUID, "-", ""), dmName) // See dm_prepare_uuid()

	kernelFlags := make([]string, 0, len(flags))
	for _, f := range flags {
		flag, ok := flagsKernelNames[f]
		if !ok {
			return fmt.Errorf("Unknown LUKS flag: %v", f)
		}
		kernelFlags = append(kernelFlags, flag)
	}

	if volume.storageSectorSize == 0 {
		return fmt.Errorf("invalid sector size")
	}
	if volume.storageSectorSize != devmapper.SectorSize {
		kernelFlags = append(kernelFlags, "sector_size:"+strconv.Itoa(int(volume.storageSectorSize)))
	}

	if volume.storageSize%volume.storageSectorSize != 0 {
		return fmt.Errorf("storage size must be multiple of sector size")
	}
	if volume.storageOffset%volume.storageSectorSize != 0 {
		return fmt.Errorf("offset must be multiple of sector size")
	}

	// the key should have hex format
	key := make([]byte, hex.EncodedLen(len(volume.key)))
	hex.Encode(key, volume.key)
	defer clearSlice(key)

	c := devmapper.CryptTable{
		StartSector:   0,
		Length:        volume.storageSize / devmapper.SectorSize,
		BackendDevice: path,
		BackendOffset: volume.storageOffset / devmapper.SectorSize,
		Encryption:    volume.storageEncryption,
		Key:           string(key),
		IVTweak:       volume.storageIvTweak,
		Flags:         kernelFlags,
	}
	return devmapper.CreateAndLoad(dmName, uuid, 0, c)
}
