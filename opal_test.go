package luks

import (
	"bytes"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestOpalStructLayout pins the field offsets of the ioctl structs to the
// kernel ABI from <linux/sed-opal.h>. Sizes are already asserted at compile
// time; offsets are checked here.
func TestOpalStructLayout(t *testing.T) {
	var k opalKeyC
	require.Equal(t, uintptr(0), unsafe.Offsetof(k.LR))
	require.Equal(t, uintptr(1), unsafe.Offsetof(k.KeyLen))
	require.Equal(t, uintptr(2), unsafe.Offsetof(k.KeyType))
	require.Equal(t, uintptr(8), unsafe.Offsetof(k.Key))

	var s opalSessionInfo
	require.Equal(t, uintptr(0), unsafe.Offsetof(s.SUM))
	require.Equal(t, uintptr(4), unsafe.Offsetof(s.Who))
	require.Equal(t, uintptr(8), unsafe.Offsetof(s.Key))

	var lu opalLockUnlock
	require.Equal(t, uintptr(0), unsafe.Offsetof(lu.Session))
	require.Equal(t, uintptr(272), unsafe.Offsetof(lu.LState))
	require.Equal(t, uintptr(276), unsafe.Offsetof(lu.Flags))

	var geo opalGeometry
	require.Equal(t, uintptr(4), unsafe.Offsetof(geo.LogicalBlockSize))
	require.Equal(t, uintptr(8), unsafe.Offsetof(geo.AlignmentGranularity))
	require.Equal(t, uintptr(16), unsafe.Offsetof(geo.LowestAlignedLBA))

	var lr opalLrStatus
	require.Equal(t, uintptr(272), unsafe.Offsetof(lr.RangeStart))
	require.Equal(t, uintptr(280), unsafe.Offsetof(lr.RangeLength))
	require.Equal(t, uintptr(288), unsafe.Offsetof(lr.RLE))
	require.Equal(t, uintptr(292), unsafe.Offsetof(lr.WLE))
	require.Equal(t, uintptr(296), unsafe.Offsetof(lr.LState))
}

func TestOpalStatusCodeToErr(t *testing.T) {
	require.NoError(t, opalStatusCodeToErr("op", 0, 0))
	require.ErrorIs(t, opalStatusCodeToErr("op", opalStatusNotAuthorized, 0), ErrOpalNotAuthorized)
	require.ErrorContains(t, opalStatusCodeToErr("op", opalStatusFail, 0), "TCG status FAIL")
	require.ErrorContains(t, opalStatusCodeToErr("op", 0x24, 0), "TCG status 0x24")
	require.ErrorIs(t, opalStatusCodeToErr("op", 0, unix.ENOTTY), unix.ENOTTY)
}

func TestFillOpalSession(t *testing.T) {
	key := []byte("secret-opal-key")
	var s opalSessionInfo
	require.NoError(t, fillOpalSession(&s, 3, key))
	require.Equal(t, uint32(0), s.SUM)
	require.Equal(t, uint32(4), s.Who) // segment number + 1, never Admin1
	require.Equal(t, uint8(3), s.Key.LR)
	require.Equal(t, opalKeyIncluded, s.Key.KeyType)
	require.Equal(t, uint8(len(key)), s.Key.KeyLen)
	require.True(t, bytes.Equal(s.Key.Key[:len(key)], key))

	require.ErrorContains(t, fillOpalSession(&s, 9, key), "segment number 9 out of range")
	require.ErrorContains(t, fillOpalSession(&s, 0, make([]byte, 256)), "exceeds maximum 255")
}

// fakeOpalCall captures one ioctl invocation made through the test seam.
type fakeOpalCall struct {
	req    uintptr
	lu     opalLockUnlock // deep copy taken at call time
	keyDup []byte
}

func withFakeOpalIoctl(t *testing.T, handler func(req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno)) *[]fakeOpalCall {
	t.Helper()
	var calls []fakeOpalCall
	orig := opalIoctl
	opalIoctl = func(fd uintptr, req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
		call := fakeOpalCall{req: req}
		if req == iocOpalLockUnlock || req == iocOpalSave {
			lu := (*opalLockUnlock)(arg)
			call.lu = *lu
			call.keyDup = append([]byte(nil), lu.Session.Key.Key[:lu.Session.Key.KeyLen]...)
		}
		calls = append(calls, call)
		return handler(req, arg)
	}
	t.Cleanup(func() { opalIoctl = orig })
	return &calls
}

func TestOpalUnlockSequence(t *testing.T) {
	calls := withFakeOpalIoctl(t, func(req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
		return 0, 0
	})

	f, err := os.CreateTemp(t.TempDir(), "fakedev")
	require.NoError(t, err)
	defer f.Close()

	key := []byte("opal-range-key")
	require.NoError(t, opalUnlock(f, 2, key))
	require.NoError(t, opalSaveUnlockForResume(f, 2, key))

	require.Len(t, *calls, 2)

	unlock := (*calls)[0]
	require.Equal(t, uintptr(iocOpalLockUnlock), unlock.req)
	require.Equal(t, opalRW, unlock.lu.LState)
	require.Equal(t, uint16(0), unlock.lu.Flags)
	require.Equal(t, uint32(3), unlock.lu.Session.Who)
	require.Equal(t, uint32(0), unlock.lu.Session.SUM)
	require.Equal(t, uint8(2), unlock.lu.Session.Key.LR)
	require.Equal(t, key, unlock.keyDup)

	save := (*calls)[1]
	require.Equal(t, uintptr(iocOpalSave), save.req)
	require.Equal(t, opalRW, save.lu.LState)
	require.Equal(t, opalSaveForLock, save.lu.Flags)
	require.Equal(t, key, save.keyDup)
}

func TestOpalUnlockNotAuthorized(t *testing.T) {
	withFakeOpalIoctl(t, func(req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
		if req == iocOpalLockUnlock {
			return opalStatusNotAuthorized, 0
		}
		return 0, 0
	})

	f, err := os.CreateTemp(t.TempDir(), "fakedev")
	require.NoError(t, err)
	defer f.Close()

	require.ErrorIs(t, opalUnlock(f, 0, []byte("bad")), ErrOpalNotAuthorized)
}

func TestOpalSaveFailureIsSeparate(t *testing.T) {
	withFakeOpalIoctl(t, func(req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
		if req == iocOpalSave {
			return 0, unix.EOPNOTSUPP
		}
		return 0, 0
	})

	f, err := os.CreateTemp(t.TempDir(), "fakedev")
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, opalUnlock(f, 0, []byte("key"))) // unlock unaffected
	require.ErrorIs(t, opalSaveUnlockForResume(f, 0, []byte("key")), unix.EOPNOTSUPP)
}

func TestOpalLockSequence(t *testing.T) {
	calls := withFakeOpalIoctl(t, func(req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
		return 0, 0
	})

	f, err := os.CreateTemp(t.TempDir(), "fakedev")
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, opalLock(f, 1, nil))
	require.Len(t, *calls, 2)

	lock := (*calls)[0]
	require.Equal(t, uintptr(iocOpalLockUnlock), lock.req)
	require.Equal(t, opalLK, lock.lu.LState)
	require.Equal(t, uint8(0), lock.lu.Session.Key.KeyLen) // kernel substitutes saved key
	require.Equal(t, uint16(0), lock.lu.Flags)

	save := (*calls)[1]
	require.Equal(t, uintptr(iocOpalSave), save.req)
	require.Equal(t, opalLK, save.lu.LState)
	require.Equal(t, uint16(0), save.lu.Flags) // overwrite saved entry: resume must re-lock
}

// TestOpalLockWithExplicitKey covers the re-lock-on-error path, where the key
// is passed explicitly because the earlier save may not have succeeded.
func TestOpalLockWithExplicitKey(t *testing.T) {
	calls := withFakeOpalIoctl(t, func(req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
		return 0, 0
	})

	f, err := os.CreateTemp(t.TempDir(), "fakedev")
	require.NoError(t, err)
	defer f.Close()

	key := []byte("opal-range-key")
	require.NoError(t, opalLock(f, 1, key))
	lock := (*calls)[0]
	require.Equal(t, opalLK, lock.lu.LState)
	require.Equal(t, key, lock.keyDup)
}

func TestVerifyOpalGeometry(t *testing.T) {
	// partition at LBA 2048, LUKS data offset 16 MiB, range 1 GiB, 512B blocks
	good := &opalLrStatus{
		RangeStart:  2048 + 16*1024*1024/512,
		RangeLength: 1024 * 1024 * 1024 / 512,
		RLE:         1,
		WLE:         1,
	}
	require.NoError(t, verifyOpalGeometry(good, 512, 2048, 16*1024*1024, 1024*1024*1024))

	// same drive reporting in 4096-byte blocks
	good4k := &opalLrStatus{
		RangeStart:  (2048 + 16*1024*1024/512) / 8,
		RangeLength: 1024 * 1024 * 1024 / 4096,
		RLE:         1,
		WLE:         1,
	}
	require.NoError(t, verifyOpalGeometry(good4k, 4096, 2048, 16*1024*1024, 1024*1024*1024))

	badStart := &opalLrStatus{RangeStart: 1, RangeLength: good.RangeLength, RLE: 1, WLE: 1}
	require.ErrorContains(t, verifyOpalGeometry(badStart, 512, 2048, 16*1024*1024, 1024*1024*1024), "starts at block")

	badLen := &opalLrStatus{RangeStart: good.RangeStart, RangeLength: 1, RLE: 1, WLE: 1}
	require.ErrorContains(t, verifyOpalGeometry(badLen, 512, 2048, 16*1024*1024, 1024*1024*1024), "blocks long")

	// a segment whose sector boundaries don't fall on drive blocks must
	// be rejected, not silently truncated by integer division
	require.ErrorContains(t, verifyOpalGeometry(good4k, 4096, 2049, 16*1024*1024, 1024*1024*1024), "not aligned to the drive's 4096-byte blocks")

	noLock := &opalLrStatus{RangeStart: good.RangeStart, RangeLength: good.RangeLength}
	require.ErrorContains(t, verifyOpalGeometry(noLock, 512, 2048, 16*1024*1024, 1024*1024*1024), "locking disabled")

	require.ErrorContains(t, verifyOpalGeometry(good, 256, 2048, 16*1024*1024, 1024*1024*1024), "unexpected logical block size")
	require.ErrorContains(t, verifyOpalGeometry(good, 1536, 2048, 16*1024*1024, 1024*1024*1024), "unexpected logical block size")
}

func TestParseOpalSegment(t *testing.T) {
	base := func() *segment {
		return &segment{
			Type:              "hw-opal",
			Offset:            "16777216",
			Size:              "1073741824",
			OpalSegmentNumber: 3,
			OpalKeySize:       32,
			OpalSegmentSize:   "1073741824",
		}
	}

	tests := []struct {
		name    string
		mod     func(*segment)
		keyLen  int
		wantErr string
	}{
		{name: "hw-opal happy path", mod: func(s *segment) {}, keyLen: 32},
		{
			name: "hw-opal-crypt happy path",
			mod: func(s *segment) {
				s.Type = "hw-opal-crypt"
				s.Encryption = "aes-xts-plain64"
				s.SectorSize = 512
			},
			keyLen: 96,
		},
		{
			name:    "dynamic size rejected",
			mod:     func(s *segment) { s.Size = "dynamic" },
			keyLen:  32,
			wantErr: `cannot be "dynamic"`,
		},
		{
			name:    "hw-opal with crypt remainder",
			mod:     func(s *segment) {},
			keyLen:  96,
			wantErr: "expects the whole keyslot key",
		},
		{
			name:    "hw-opal-crypt key too short",
			mod:     func(s *segment) { s.Type = "hw-opal-crypt" },
			keyLen:  32,
			wantErr: "leaves no dm-crypt key",
		},
		{
			name:    "zero key size",
			mod:     func(s *segment) { s.OpalKeySize = 0 },
			keyLen:  32,
			wantErr: "no opal_key_size",
		},
		{
			name:    "key size above kernel limit",
			mod:     func(s *segment) { s.OpalKeySize = 256 },
			keyLen:  256,
			wantErr: "exceeds maximum 255",
		},
		{
			name:    "segment number above kernel limit",
			mod:     func(s *segment) { s.OpalSegmentNumber = 9 },
			keyLen:  32,
			wantErr: "out of range",
		},
		{
			name:    "unaligned locking range",
			mod:     func(s *segment) { s.OpalSegmentSize = "1073741825"; s.Size = "1024" },
			keyLen:  32,
			wantErr: "not 512-byte aligned",
		},
		{
			name:    "unaligned offset",
			mod:     func(s *segment) { s.Offset = "100" },
			keyLen:  32,
			wantErr: "not 512-byte aligned",
		},
		{
			name:    "data segment size differs from locking range",
			mod:     func(s *segment) { s.OpalSegmentSize = "512" },
			keyLen:  32,
			wantErr: "must equal OPAL locking-range size",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seg := base()
			tc.mod(seg)
			p, err := parseOpalSegment(seg, tc.keyLen)
			if tc.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, uint(3), p.segmentNumber)
				require.Equal(t, uint64(32), p.keySize)
				require.Equal(t, uint64(1073741824), p.segmentSize)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

// TestOpalRealHardware exercises the full unlock path against a real OPAL
// LUKS2 device. It requires SED hardware, root, and a device formatted with
// cryptsetup --hw-opal or --hw-opal-only, so it is gated behind environment
// variables and never runs in CI (QEMU cannot emulate OPAL):
//
//	sudo LUKS_OPAL_TEST_DEVICE=/dev/nvme0n1p3 LUKS_OPAL_TEST_PASSPHRASE=... \
//	    go test -run TestOpalRealHardware -v .
func TestOpalRealHardware(t *testing.T) {
	dev := os.Getenv("LUKS_OPAL_TEST_DEVICE")
	pass := os.Getenv("LUKS_OPAL_TEST_PASSPHRASE")
	if dev == "" || pass == "" {
		t.Skip("set LUKS_OPAL_TEST_DEVICE and LUKS_OPAL_TEST_PASSPHRASE to run against real OPAL hardware")
	}

	d, err := Open(dev)
	require.NoError(t, err)
	defer d.Close()

	const name = "luksgo-opal-test"
	require.NoError(t, d.UnlockAny([]byte(pass), name))
	defer func() { require.NoError(t, Lock(name)) }()

	// The dm device exists as soon as UnlockAny returns, but the
	// /dev/mapper symlink is created asynchronously by udev.
	path := "/dev/mapper/" + name
	var m *os.File
	for range 100 {
		if m, err = os.Open(path); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NoError(t, err, "waiting for %s", path)
	defer m.Close()

	// the mapped device must expose readable plaintext
	buf := make([]byte, 4096)
	_, err = m.Read(buf)
	require.NoError(t, err)
}
