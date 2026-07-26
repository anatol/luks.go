package luks

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Bindings for the Linux SED OPAL interface (CONFIG_BLK_SED_OPAL,
// <linux/sed-opal.h>). Only the subset needed to unlock and re-lock a
// locking range that cryptsetup configured at luksFormat time.

// The ioctl request numbers below are precomputed with the asm-generic _IOC
// encoding (dir<<30 | size<<16 | type<<8 | nr), which holds for amd64, 386,
// arm, arm64, riscv64 and s390x. powerpc, mips and sparc use different
// _IOC_* bit layouts and would need per-arch values.
const (
	iocOpalSave        = 0x411870DC // _IOW('p', 220, struct opal_lock_unlock)
	iocOpalLockUnlock  = 0x411870DD // _IOW('p', 221, struct opal_lock_unlock)
	iocOpalGetStatus   = 0x800870EC // _IOR('p', 236, struct opal_status)
	iocOpalGetLrStatus = 0x413070ED // _IOW('p', 237, struct opal_lr_status); result copied back
	iocOpalGetGeometry = 0x802070EE // _IOR('p', 238, struct opal_geometry)

	// enum opal_lock_state
	opalRO uint32 = 0x01
	opalRW uint32 = 0x02
	opalLK uint32 = 0x04

	// enum opal_lock_flags
	opalSaveForLock uint16 = 0x01

	// enum opal_key_type
	opalKeyIncluded uint8 = 0

	// struct opal_status flags
	opalFlSupported        uint32 = 0x01
	opalFlLockingSupported uint32 = 0x02
	opalFlLockingEnabled   uint32 = 0x04
	opalFlLocked           uint32 = 0x08

	// TCG method status codes returned as positive values by sed ioctls
	opalStatusNotAuthorized = 0x01
	opalStatusFail          = 0x3f

	opalKeyMax = 256
	// struct opal_key.key_len is a __u8, so the largest representable key
	// is one byte shorter than the key array
	opalKeyMaxLen = 255

	// who = segment number + 1 must not exceed OPAL_USER9 (9)
	opalMaxSegmentNumber = 8
)

// Layouts mirror <linux/sed-opal.h>. All fields are fixed-width with
// explicit padding, so the Go structs match the C ABI on all 64-bit
// architectures. Sizes are asserted at compile time below; a silent
// mismatch would corrupt the ioctl arguments.

type opalKeyC struct {
	LR      uint8
	KeyLen  uint8
	KeyType uint8 // must be opalKeyIncluded; OPAL_KEYRING would make the kernel ignore Key
	pad     [5]uint8
	Key     [opalKeyMax]uint8
}

type opalSessionInfo struct {
	SUM uint32
	Who uint32
	Key opalKeyC
}

type opalLockUnlock struct {
	Session opalSessionInfo
	LState  uint32
	Flags   uint16
	pad     [2]uint8
}

type opalStatus struct {
	Flags    uint32
	Reserved uint32
}

type opalGeometry struct {
	Align                uint8
	pad0                 [3]uint8
	LogicalBlockSize     uint32
	AlignmentGranularity uint64
	LowestAlignedLBA     uint64
	pad1                 [8]uint8
}

type opalLrStatus struct {
	Session     opalSessionInfo
	RangeStart  uint64
	RangeLength uint64
	RLE         uint32
	WLE         uint32
	LState      uint32
	pad         [4]uint8
}

// compile-time layout assertions against the kernel ABI
var (
	_ = [1]struct{}{}[unsafe.Sizeof(opalKeyC{})-264]
	_ = [1]struct{}{}[unsafe.Sizeof(opalSessionInfo{})-272]
	_ = [1]struct{}{}[unsafe.Sizeof(opalLockUnlock{})-280]
	_ = [1]struct{}{}[unsafe.Sizeof(opalStatus{})-8]
	_ = [1]struct{}{}[unsafe.Sizeof(opalGeometry{})-32]
	_ = [1]struct{}{}[unsafe.Sizeof(opalLrStatus{})-304]
)

// ErrOpalNotAuthorized means the drive rejected the locking-range key. It is
// deliberately distinct from ErrPassphraseDoesNotMatch: by the time an OPAL
// ioctl runs, the passphrase has already passed LUKS digest verification, so
// the header and the drive credential have diverged (e.g. after a factory
// reset) and re-prompting the user cannot help.
var ErrOpalNotAuthorized = errors.New("OPAL: drive not authorized (locking-range key does not match LUKS header)")

// opalIoctl is the single impure call in this file, indirected so unit tests
// can substitute a fake without OPAL hardware.
var opalIoctl = func(fd uintptr, req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
	r1, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, req, uintptr(arg))
	// unix.Syscall lacks the //go:uintptrkeepalive pragma of the syscall
	// package, so keep the argument struct reachable across the call
	// ourselves.
	runtime.KeepAlive(arg)
	return r1, errno
}

// opalStatusCodeToErr interprets the tri-state sed ioctl result: the ioctl
// returns -errno (delivered as errno here), 0 for success, or a positive TCG
// method status code.
func opalStatusCodeToErr(op string, ret uintptr, errno unix.Errno) error {
	if errno != 0 {
		return fmt.Errorf("OPAL %s: %w", op, errno)
	}
	switch ret {
	case 0:
		return nil
	case opalStatusNotAuthorized:
		return fmt.Errorf("OPAL %s: %w", op, ErrOpalNotAuthorized)
	case opalStatusFail:
		return fmt.Errorf("OPAL %s: TCG status FAIL", op)
	default:
		return fmt.Errorf("OPAL %s: TCG status 0x%x", op, ret)
	}
}

// fillOpalSession fills the session header shared by all locking-range
// operations directly into the caller's struct, so the key material exists in
// exactly one place (which the caller clears): the range is owned by user
// (segment number + 1), never Admin1, and SUM is always 0 (even on Single
// User Mode drives the range's User authority performs lock/unlock).
func fillOpalSession(s *opalSessionInfo, segmentNumber uint, key []byte) error {
	if segmentNumber > opalMaxSegmentNumber {
		return fmt.Errorf("OPAL segment number %d out of range: the kernel supports locking ranges 0..%d", segmentNumber, opalMaxSegmentNumber)
	}
	if len(key) > opalKeyMaxLen {
		return fmt.Errorf("OPAL key length %d exceeds maximum %d", len(key), opalKeyMaxLen)
	}
	s.SUM = 0
	s.Who = uint32(segmentNumber) + 1
	s.Key.LR = uint8(segmentNumber)
	s.Key.KeyType = opalKeyIncluded
	s.Key.KeyLen = uint8(len(key))
	copy(s.Key.Key[:], key)
	return nil
}

func opalGetStatusIoctl(f *os.File) (*opalStatus, error) {
	var st opalStatus
	ret, errno := opalIoctl(f.Fd(), iocOpalGetStatus, unsafe.Pointer(&st))
	if err := opalStatusCodeToErr("get status", ret, errno); err != nil {
		return nil, err
	}
	return &st, nil
}

func opalGetGeometryIoctl(f *os.File) (*opalGeometry, error) {
	var geo opalGeometry
	ret, errno := opalIoctl(f.Fd(), iocOpalGetGeometry, unsafe.Pointer(&geo))
	if err := opalStatusCodeToErr("get geometry", ret, errno); err != nil {
		return nil, err
	}
	return &geo, nil
}

func opalGetLrStatusIoctl(f *os.File, segmentNumber uint, key []byte) (*opalLrStatus, error) {
	var lr opalLrStatus
	if err := fillOpalSession(&lr.Session, segmentNumber, key); err != nil {
		return nil, err
	}
	// The key is zeroed before the caller sees the struct: callers only
	// consume the range/lock-state fields, never the session key.
	defer clearSlice(lr.Session.Key.Key[:])

	ret, errno := opalIoctl(f.Fd(), iocOpalGetLrStatus, unsafe.Pointer(&lr))
	if err := opalStatusCodeToErr("get locking range status", ret, errno); err != nil {
		return nil, err
	}
	return &lr, nil
}

// opalUnlock unlocks the given locking range for read-write.
func opalUnlock(f *os.File, segmentNumber uint, key []byte) error {
	var lu opalLockUnlock
	if err := fillOpalSession(&lu.Session, segmentNumber, key); err != nil {
		return err
	}
	defer clearSlice(lu.Session.Key.Key[:])
	lu.LState = opalRW

	ret, errno := opalIoctl(f.Fd(), iocOpalLockUnlock, unsafe.Pointer(&lu))
	return opalStatusCodeToErr("unlock", ret, errno)
}

// opalSaveUnlockForResume asks the kernel to remember the unlock key
// (OPAL_SAVE_FOR_LOCK) so the range is re-unlocked transparently on resume
// from S3 suspend, and so a later keyless opalLock can rely on the stored
// key. SAVE never talks to the drive; it only updates the kernel's suspend
// list, so a failure affects resume behavior, not the current unlock.
func opalSaveUnlockForResume(f *os.File, segmentNumber uint, key []byte) error {
	var lu opalLockUnlock
	if err := fillOpalSession(&lu.Session, segmentNumber, key); err != nil {
		return err
	}
	defer clearSlice(lu.Session.Key.Key[:])
	lu.LState = opalRW
	lu.Flags = opalSaveForLock

	ret, errno := opalIoctl(f.Fd(), iocOpalSave, unsafe.Pointer(&lu))
	return opalStatusCodeToErr("save", ret, errno)
}

// opalLock re-locks the locking range. With a nil key the kernel substitutes
// the key stored by an earlier successful opalSaveUnlockForResume; pass the
// key explicitly when that save is not known to have succeeded. The follow-up
// SAVE records the locked state so resume from S3 re-locks rather than
// unlocks; its failure is non-fatal since the range is already locked.
func opalLock(f *os.File, segmentNumber uint, key []byte) error {
	var lu opalLockUnlock
	if err := fillOpalSession(&lu.Session, segmentNumber, key); err != nil {
		return err
	}
	defer clearSlice(lu.Session.Key.Key[:])
	lu.LState = opalLK

	ret, errno := opalIoctl(f.Fd(), iocOpalLockUnlock, unsafe.Pointer(&lu))
	if err := opalStatusCodeToErr("lock", ret, errno); err != nil {
		return err
	}

	ret, errno = opalIoctl(f.Fd(), iocOpalSave, unsafe.Pointer(&lu))
	_ = opalStatusCodeToErr("save", ret, errno)
	return nil
}

// opalParams is the validated OPAL geometry of a "hw-opal" or "hw-opal-crypt"
// segment.
type opalParams struct {
	segmentNumber uint
	keySize       uint64 // bytes; prefix of the keyslot key holding the OPAL passphrase
	segmentSize   uint64 // locking-range length in bytes
}

// parseOpalSegment validates the OPAL fields of a segment against the keyslot
// key length, mirroring the constraints cryptsetup's header validator
// guarantees and the kernel enforces.
func parseOpalSegment(seg *segment, keyLen int) (*opalParams, error) {
	if seg.Size == "dynamic" {
		return nil, fmt.Errorf(`OPAL segment size cannot be "dynamic"`)
	}
	size, err := strconv.ParseUint(seg.Size, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid OPAL segment size %q: %w", seg.Size, err)
	}
	offset, err := seg.Offset.Int64()
	if err != nil {
		return nil, fmt.Errorf("invalid OPAL segment offset %q: %w", seg.Offset, err)
	}
	if offset%512 != 0 || size%512 != 0 {
		return nil, fmt.Errorf("OPAL segment offset %d / size %d not 512-byte aligned", offset, size)
	}

	keySize := uint64(seg.OpalKeySize)
	switch {
	case keySize == 0:
		return nil, fmt.Errorf("OPAL segment has no opal_key_size")
	case keySize > opalKeyMaxLen:
		return nil, fmt.Errorf("opal_key_size %d exceeds maximum %d", keySize, opalKeyMaxLen)
	case seg.Type == "hw-opal" && keySize != uint64(keyLen):
		return nil, fmt.Errorf("hw-opal segment expects the whole keyslot key (%d bytes) as OPAL key, got opal_key_size %d", keyLen, keySize)
	case seg.Type == "hw-opal-crypt" && keySize >= uint64(keyLen):
		return nil, fmt.Errorf("hw-opal-crypt opal_key_size %d leaves no dm-crypt key in the %d-byte keyslot key", keySize, keyLen)
	}

	if seg.OpalSegmentNumber > opalMaxSegmentNumber {
		return nil, fmt.Errorf("OPAL segment number %d out of range: the kernel supports locking ranges 0..%d", seg.OpalSegmentNumber, opalMaxSegmentNumber)
	}

	segmentSize, err := strconv.ParseUint(seg.OpalSegmentSize, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid opal_segment_size %q: %w", seg.OpalSegmentSize, err)
	}
	if segmentSize == 0 || segmentSize%512 != 0 {
		return nil, fmt.Errorf("opal_segment_size %d is zero or not 512-byte aligned", segmentSize)
	}
	// cryptsetup requires the data segment and the locking range to have
	// the same size (a smaller segment is only allowed with integrity
	// layouts, which this library does not support for OPAL).
	if size != segmentSize {
		return nil, fmt.Errorf("segment size %d must equal OPAL locking-range size %d", size, segmentSize)
	}

	return &opalParams{
		segmentNumber: seg.OpalSegmentNumber,
		keySize:       keySize,
		segmentSize:   segmentSize,
	}, nil
}

// partitionStartSector returns the start LBA (in 512-byte sectors) of the
// given open partition block device. The sysfs node is looked up via the
// device's major:minor so that symlinked paths (/dev/disk/by-uuid/... etc.)
// resolve correctly. Whole-disk devices have no `start` attribute and yield
// 0, which is also the correct offset for them.
func partitionStartSector(f *os.File) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return 0, fmt.Errorf("%s is not a block device", f.Name())
	}
	rdev := uint64(st.Rdev)
	sysfsPath := fmt.Sprintf("/sys/dev/block/%d:%d/start", unix.Major(rdev), unix.Minor(rdev))
	data, err := os.ReadFile(sysfsPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil // whole disk
	}
	if err != nil {
		return 0, err
	}
	start, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing partition start of %s: %w", f.Name(), err)
	}
	return start, nil
}

// isOpalQueryUnsupported reports whether an error from a status/geometry
// query means the kernel or firmware genuinely cannot answer it (as opposed
// to refusing it, e.g. NOT_AUTHORIZED, which callers must treat as fatal).
func isOpalQueryUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS)
}

// verifyOpalGeometry checks that the locking range the drive reports matches
// what the LUKS2 header promises: the range must cover exactly the data
// segment (offset relative to the partition plus the partition's own start)
// and have both read and write lock enabled. A mismatch means the header and
// the drive configuration have diverged; unlocking anyway would expose wrong
// ciphertext as if it were the volume.
func verifyOpalGeometry(lr *opalLrStatus, logicalBlockSize uint32, partStartSector, storageOffsetBytes, opalSegmentSizeBytes uint64) error {
	if logicalBlockSize < 512 || !isPowerOfTwo(uint(logicalBlockSize)) {
		return fmt.Errorf("OPAL: unexpected logical block size %d", logicalBlockSize)
	}
	sectorsPerBlock := uint64(logicalBlockSize) / 512

	// Compare in drive-block units: multiplying the drive-reported values
	// could wrap and defeat the comparison.
	wantStart := storageOffsetBytes/512 + partStartSector
	wantLength := opalSegmentSizeBytes / 512
	if wantStart%sectorsPerBlock != 0 || wantLength%sectorsPerBlock != 0 {
		return fmt.Errorf("OPAL segment (start sector %d, length %d) is not aligned to the drive's %d-byte blocks", wantStart, wantLength, logicalBlockSize)
	}

	if lr.RangeStart != wantStart/sectorsPerBlock {
		return fmt.Errorf("OPAL locking range starts at block %d, LUKS header expects %d", lr.RangeStart, wantStart/sectorsPerBlock)
	}
	if lr.RangeLength != wantLength/sectorsPerBlock {
		return fmt.Errorf("OPAL locking range is %d blocks long, LUKS header expects %d", lr.RangeLength, wantLength/sectorsPerBlock)
	}
	if lr.RLE == 0 || lr.WLE == 0 {
		return fmt.Errorf("OPAL locking range has locking disabled (RLE=%d WLE=%d)", lr.RLE, lr.WLE)
	}
	return nil
}
