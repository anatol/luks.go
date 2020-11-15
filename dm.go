package luks

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func createDmDevice(path string, dmName string, partitionUuid string, volume *volumeInfo) error {
	// load key into keyring
	keyname := fmt.Sprintf("cryptsetup:%s-d%d", partitionUuid, volume.digestId) // get_key_description_by_digest
	kid, err := unix.AddKey("logon", keyname, volume.key, unix.KEY_SPEC_THREAD_KEYRING)
	if err != nil {
		return err
	}
	clearSlice(volume.key)
	defer unlinkKey(kid)

	// call dm-crypt ioctls() see _dm_create_device() and _do_dm_ioctl()
	controlFile, err := os.Open("/dev/mapper/control")
	if err != nil {
		return err
	}
	defer controlFile.Close()

	uuid := fmt.Sprintf("CRYPT-%v-%v-%v", volume.luksType, strings.ReplaceAll(partitionUuid, "-", ""), dmName) // See dm_prepare_uuid()

	// A good explanation of dmsetup use is described here https://wiki.gentoo.org/wiki/Device-mapper
	// dmsetup create test-crypt --table '0 1953125 crypt aes-xts-plain64 :32:user:test-cryptkey 0 /dev/loop0 0 1 allow_discards'
	// parameters are based on https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-crypt.html
	if err := dmIoctl(controlFile, unix.DM_DEV_CREATE, dmName, uuid, nil); err != nil {
		return err
	}

	keyid := fmt.Sprintf(":%v:logon:%v", len(volume.key), keyname)
	storageArg := fmt.Sprintf("%v %v %v %v %v %v", volume.storageEncryption, keyid, volume.storageIvTweak, path, volume.storageOffset, "0") // see get_dm_crypt_params() for more info about formatting this parameter

	spec := []targetSpec{{
		sectorStart: 0, // always zero
		length:      volume.storageSize,
		targetType:  "crypt",
		args:        storageArg,
	}}

	if err := dmIoctl(controlFile, unix.DM_TABLE_LOAD, dmName, "", spec); err != nil {
		_ = Lock(dmName)
		return err
	}

	if err := dmIoctl(controlFile, unix.DM_DEV_SUSPEND, dmName, "", nil); err != nil {
		_ = Lock(dmName)
		return err
	}

	return nil
}

type targetSpec struct {
	sectorStart uint64 // these values are set by dm_crypt_target_set()
	length      uint64
	targetType  string
	args        string // see how it is generated at get_dm_crypt_params()
}

func dmIoctl(controlFile *os.File, cmd int, name string, uuid string, specs []targetSpec) error {
	// allocate buffer large enough for dmioctl + specs
	const alignment = 8

	length := unix.SizeofDmIoctl
	for _, s := range specs {
		length += unix.SizeofDmTargetSpec
		length += roundUp(len(s.args)+1, alignment) // adding 1 for terminating NUL, then align the data
	}

	data := make([]byte, length, length)
	var idx uintptr
	ioctlData := (*unix.DmIoctl)(unsafe.Pointer(&data[idx]))
	ioctlData.Version = [...]uint32{4, 0, 0} // minimum required version
	copy(ioctlData.Name[:], name)
	copy(ioctlData.Uuid[:], uuid)
	ioctlData.Data_size = uint32(length)
	ioctlData.Data_start = unix.SizeofDmIoctl
	ioctlData.Target_count = uint32(len(specs))
	idx += unix.SizeofDmIoctl

	for _, s := range specs {
		specData := (*unix.DmTargetSpec)(unsafe.Pointer(&data[idx]))
		specSize := unix.SizeofDmTargetSpec + uintptr(roundUp(len(s.args)+1, alignment))
		specData.Next = uint32(specSize)
		specData.Sector_start = s.sectorStart
		specData.Length = s.length
		copy(specData.Target_type[:], s.targetType)
		copy(data[idx+unix.SizeofDmTargetSpec:], s.args)

		idx += specSize
	}

	_, _, err := syscall.Syscall(syscall.SYS_IOCTL,
		controlFile.Fd(),
		uintptr(cmd),
		uintptr(unsafe.Pointer(&data[0])),
	)
	if err != 0 {
		return os.NewSyscallError(fmt.Sprintf("dm ioctl (cmd=0x%x)", cmd), err)
	}
	return nil
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
