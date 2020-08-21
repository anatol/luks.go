package luks

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// error that indicates provided passphrase does not match
var ErrPassphraseDoesNotMatch = fmt.Errorf("Passphrase does not match")

// a parameter that indicates passphrase should be tried with all active slots
const AnyKeyslot = -1

type volumeInfo struct {
	key               []byte
	digestId          int // id of the digest that matches the key
	luksType          string
	storageEncryption string
	storageIvTweak    uint64
	storageSectorSize uint64
	storageOffset     uint64 // offset of underlying storage in sectors
	storageSize       uint64 // length of underlying device in sectors, zero means that size should be calculated using `diskSize` function
}

type luksDevice interface {
	unlockKeyslot(f *os.File, keyslotIdx int, passphrase []byte) (*volumeInfo, error)
	unlockAnyKeyslot(f *os.File, passphrase []byte) (*volumeInfo, error)
	uuid() string
}

// default sector size
const storageSectorSize = 512

// default number of anti-forensic stripes
const stripesNum = 4000

func Open(dev string, name string, keyslot int, passphrase []byte) error {
	f, err := os.Open(dev)
	if err != nil {
		return err
	}
	defer f.Close()

	// LUKS Magic and versions are stored in the first 8 bytes of the LUKS header
	header := make([]byte, 8)
	if _, err := f.ReadAt(header[:], 0); err != nil {
		return err
	}

	// verify header magic
	if !bytes.Equal(header[0:6], []byte("LUKS\xba\xbe")) {
		return fmt.Errorf("invalid LUKS header")
	}

	luks, err := luksOpen(header, f)
	if err != nil {
		return err
	}

	var volume *volumeInfo
	if keyslot == AnyKeyslot {
		volume, err = luks.unlockAnyKeyslot(f, passphrase)
	} else {
		volume, err = luks.unlockKeyslot(f, keyslot, passphrase)
	}
	if err != nil {
		return err
	}
	defer clearSlice(volume.key)

	if volume.storageSize == 0 {
		volume.storageSize, err = calculatePartitionSize(f, volume)
		if err != nil {
			return err
		}
	}

	return createDmDevice(dev, name, luks.uuid(), volume)
}

func luksOpen(header []byte, f *os.File) (luksDevice, error) {
	version := int(header[6])<<8 + int(header[7])

	switch version {
	case 1:
		return luks1OpenDevice(f)
	case 2:
		return luks2OpenDevice(f)
	default:
		return nil, fmt.Errorf("invalid LUKS version %v", version)
	}
}

func createDmDevice(dev string, dmName string, partitionUuid string, volume *volumeInfo) error {
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
	storageArg := fmt.Sprintf("%v %v %v %v %v %v", volume.storageEncryption, keyid, volume.storageIvTweak, dev, volume.storageOffset, "0") // see get_dm_crypt_params() for more info about formatting this parameter

	spec := []targetSpec{{
		sectorStart: 0, // always zero
		length:      volume.storageSize,
		targetType:  "crypt",
		args:        storageArg,
	}}

	if err := dmIoctl(controlFile, unix.DM_TABLE_LOAD, dmName, "", spec); err != nil {
		_ = Close(dmName)
		return err
	}

	if err := dmIoctl(controlFile, unix.DM_DEV_SUSPEND, dmName, "", nil); err != nil {
		_ = Close(dmName)
		return err
	}

	return nil
}

// calculatePartitionSize dynamically calculates the size of storage in sector size
func calculatePartitionSize(f *os.File, volumeKey *volumeInfo) (uint64, error) {
	s, err := unix.IoctlGetInt(int(f.Fd()), unix.BLKGETSIZE64)
	if err != nil {
		return 0, err
	}

	size := uint64(s) / volumeKey.storageSectorSize
	if size < volumeKey.storageOffset {
		return 0, fmt.Errorf("Block file size %v is smaller than LUKS segment offset %v", s, volumeKey.storageOffset)
	}
	return size - volumeKey.storageOffset, nil
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

// Close closes device mapper partition with the given name
func Close(name string) error {
	controlFile, err := os.Open("/dev/mapper/control")
	if err != nil {
		return err
	}
	defer controlFile.Close()

	return dmIoctl(controlFile, unix.DM_DEV_REMOVE, name, "", nil)
}
