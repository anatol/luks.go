package luks

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/anatol/devmapper.go"
)

func createDmDevice(path string, dmName string, partitionUuid string, volume *volumeInfo, flags []string) error {
	uuid := fmt.Sprintf("CRYPT-%v-%v-%v", volume.luksType, strings.ReplaceAll(partitionUuid, "-", ""), dmName) // See dm_prepare_uuid()

	kernelFlags := make([]string, 0, len(flags))
	for _, f := range flags {
		flag, ok := flagsKernelNames[f]
		if !ok {
			return fmt.Errorf("Unknown LUKS flag: %v", f)
		}
		kernelFlags = append(kernelFlags, flag)
	}

	// the key should have hex format
	key := make([]byte, hex.EncodedLen(len(volume.key)))
	hex.Encode(key, volume.key)
	defer clearSlice(key)

	c := devmapper.CryptTable{
		StartSector:   0,
		Length:        volume.storageSize,
		BackendDevice: path,
		BackendOffset: volume.storageOffset,
		Encryption:    volume.storageEncryption,
		Key:           string(key),
		IVTweak:       volume.storageIvTweak,
		Flags:         kernelFlags,
	}
	return devmapper.CreateAndLoad(dmName, uuid, 0, c)
}
