package luks

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

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
	if err := dmIoctl(controlFile, unix.DM_DEV_CREATE, dmName, uuid, false, nil); err != nil {
		return err
	}

	keyid := fmt.Sprintf(":%v:logon:%v", len(volume.key), keyname)
	// see get_dm_crypt_params() for more info about this parameter formatting
	storageArg := []string{volume.storageEncryption, keyid, strconv.Itoa(int(volume.storageIvTweak)), path, strconv.Itoa(int(volume.storageOffset))}
	storageArg = append(storageArg, strconv.Itoa(len(flags)))
	for _, f := range flags {
		kernelFlag, ok := flagsKernelNames[f]
		if !ok {
			return fmt.Errorf("Unknown LUKS flag: %v", f)
		}
		storageArg = append(storageArg, kernelFlag)
	}

	spec := []targetSpec{{
		sectorStart: 0, // always zero
		length:      volume.storageSize,
		targetType:  "crypt",
		args:        strings.Join(storageArg, " "),
	}}

	if err := dmIoctl(controlFile, unix.DM_TABLE_LOAD, dmName, "", false, spec); err != nil {
		_ = Lock(dmName)
		return err
	}

	// it is actually a resume operation
	if err := dmIoctl(controlFile, unix.DM_DEV_SUSPEND, dmName, "", true, nil); err != nil {
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

// dmIoctl executes a device mapper ioctl
// udevEvent is a boolean field that sets DM_UDEV_PRIMARY_SOURCE_FLAG udev flag.
// This flag is later processed by rules at /usr/lib/udev/rules.d/10-dm.rules
// Per devicecrypt sourcecode only RESUME, REMOVE, RENAME operations need to have DM_UDEV_PRIMARY_SOURCE_FLAG
// flag set.
func dmIoctl(controlFile *os.File, cmd int, name string, uuid string, udevEvent bool, specs []targetSpec) error {
	const (
		// allocate buffer large enough for dmioctl + specs
		alignment = 8

		DM_UDEV_FLAGS_SHIFT = 16
		// Quoting https://fossies.org/linux/LVM2/libdm/libdevmapper.h
		//
		// DM_UDEV_PRIMARY_SOURCE_FLAG is automatically appended by
		// libdevmapper for all ioctls generating udev uevents. Once used in
		// udev rules, we know if this is a real "primary sourced" event or not.
		// We need to distinguish real events originated in libdevmapper from
		// any spurious events to gather all missing information (e.g. events
		// generated as a result of "udevadm trigger" command or as a result
		// of the "watch" udev rule).
		DM_UDEV_PRIMARY_SOURCE_FLAG = 0x0040
	)

	var udevFlags uint32
	if udevEvent {
		// device mapper has a complex initialization sequence. A device need to be 1) created
		// 2) load table 3) resumed. The device is usable at the 3rd step only.
		// To make udev rules handle the device at 3rd step (rather than at ADD event), device mapper distinguishes
		// the "primary" events with a udev flag set below.
		// Only RESUME, REMOVE, RENAME operations are considered primary events.
		udevFlags = DM_UDEV_PRIMARY_SOURCE_FLAG << DM_UDEV_FLAGS_SHIFT
	}

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
	ioctlData.Event_nr = udevFlags
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
