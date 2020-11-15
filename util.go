package luks

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

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

// default sector size
const storageSectorSize = 512

// default number of anti-forensic stripes
const stripesNum = 4000

// computePartitionSize dynamically calculates the size of storage in sector size
func computePartitionSize(f *os.File, volumeKey *volumeInfo) (uint64, error) {
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

func isPowerOfTwo(x uint) bool {
	return (x & (x - 1)) == 0
}

func roundUp(n int, divider int) int {
	return (n + divider - 1) / divider * divider
}

func fixedArrayToString(buff []byte) string {
	idx := bytes.IndexByte(buff, 0)
	if idx != -1 {
		buff = buff[:idx]
	}
	return string(buff)
}

func clearSlice(slice []byte) {
	for i, _ := range slice {
		slice[i] = 0
	}
}
