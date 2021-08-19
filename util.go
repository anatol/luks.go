package luks

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sys/unix"
)

type volumeInfo struct {
	key               []byte
	digestID          int // id of the digest that matches the key
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
	for i := range slice {
		slice[i] = 0
	}
}

// getHashAlgo gets hash implementation and the hash size by its name
// If hash is not found then it returns nil as a first argument
func getHashAlgo(name string) (func() hash.Hash, int) {
	// Note that cryptsetup support a few more hash algorithms not implemented here: whirlpool, stribog256, stribog512, sm3
	// golang lib does not implement those
	// TODO use third-party implementations for other hashes and add its support to luks.go
	switch name {
	case "sha1":
		return sha1.New, sha1.Size
	case "sha224":
		return sha256.New224, sha256.Size224
	case "sha256":
		return sha256.New, sha256.Size
	case "sha384":
		return sha512.New384, sha512.Size384
	case "sha512":
		return sha512.New, sha512.Size
	case "sha3-224":
		return sha3.New224, 224 / 8
	case "sha3-256":
		return sha3.New256, 256 / 8
	case "sha3-384":
		return sha3.New384, 384 / 8
	case "sha3-512":
		return sha3.New512, 512 / 8
	case "ripemd160":
		return ripemd160.New, ripemd160.Size
	default:
		return nil, 0
	}
}
