package luks

import (
	"fmt"
	"strings"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

func createDmDevice(path string, dmName string, partitionUuid string, volume *volumeInfo, flags []string) error {
	// load key into keyring
	keyname := fmt.Sprintf("cryptsetup:%s-d%d", partitionUuid, volume.digestId) // get_key_description_by_digest
	kid, err := unix.AddKey("logon", keyname, volume.key, unix.KEY_SPEC_THREAD_KEYRING)
	if err != nil {
		return err
	}
	clearSlice(volume.key)
	defer unlinkKey(kid)

	uuid := fmt.Sprintf("CRYPT-%v-%v-%v", volume.luksType, strings.ReplaceAll(partitionUuid, "-", ""), dmName) // See dm_prepare_uuid()
	keyid := fmt.Sprintf(":%v:logon:%v", len(volume.key), keyname)

	kernelFlags := make([]string, 0, len(flags))
	for _, f := range flags {
		flag, ok := flagsKernelNames[f]
		if !ok {
			return fmt.Errorf("Unknown LUKS flag: %v", f)
		}
		kernelFlags = append(kernelFlags, flag)
	}

	c := devmapper.CryptTable{
		StartSector:   0,
		Length:        volume.storageSize,
		BackendDevice: path,
		BackendOffset: int(volume.storageOffset),
		Encryption:    volume.storageEncryption,
		Key:           keyid,
		IVTweak:       int(volume.storageIvTweak),
		Flags:         kernelFlags,
	}
	return devmapper.CreateAndLoad(dmName, uuid, c)
}

func unlinkKey(kid int) {
	if _, err := unix.KeyctlInt(unix.KEYCTL_REVOKE, kid, 0, 0, 0); err != nil {
		fmt.Printf("key revoke: %v\n", err)
	}

	if _, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, kid, unix.KEY_SPEC_THREAD_KEYRING, 0, 0); err != nil {
		fmt.Printf("key unlink, thread: %v\n", err)
	}

	// We added key to thread keyring only. But let's try to unlink the key from other keyrings as well just to be safe
	_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, kid, unix.KEY_SPEC_PROCESS_KEYRING, 0, 0)
	_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, kid, unix.KEY_SPEC_USER_KEYRING, 0, 0)
}
