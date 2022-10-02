package luks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"syscall"

	"github.com/dgryski/go-camellia"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/twofish"
	"golang.org/x/sys/unix"
)

// default sector size
const storageSectorSize = 512

// default number of anti-forensic stripes
const stripesNum = 4000

// fileSize returns size of the file. This function works both with regular files and block devices
func fileSize(f *os.File) (uint64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}

	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unable to get stat for file %s", f.Name())
	}
	if sys.Mode&syscall.S_IFBLK == 0 {
		return uint64(sys.Size), nil
	}

	sz, err := unix.IoctlGetInt(int(f.Fd()), unix.BLKGETSIZE64)
	return uint64(sz), err
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
	case "blake2b-160":
		return blake2bConstructor(160)
	case "blake2b-256":
		return blake2bConstructor(256)
	case "blake2b-384":
		return blake2bConstructor(384)
	case "blake2b-512":
		return blake2bConstructor(512)
	case "blake2s-256":
		// blake2s-{128,160,224} are not supported by golang crypto library
		return blake2s256Constructor()
	default:
		return nil, 0
	}
}

func getCipher(name string) (func(key []byte) (cipher.Block, error), error) {
	switch name {
	case "aes":
		return aes.NewCipher, nil
	case "camellia":
		return camellia.New, nil
	case "twofish":
		f := func(key []byte) (cipher.Block, error) {
			// twofish.NewCipher returns Cipher type, convert it to cipher.Block
			return twofish.NewCipher(key)
		}
		return f, nil
	default:
		return nil, fmt.Errorf("Unknown cipher: %v", name)
	}
}

func blake2bConstructor(size int) (func() hash.Hash, int) {
	size = size / 8
	return func() hash.Hash {
		h, err := blake2b.New(size, nil)
		if err != nil {
			panic(err)
		}
		return h
	}, size
}

func blake2s256Constructor() (func() hash.Hash, int) {
	return func() hash.Hash {
		h, err := blake2s.New256(nil)
		if err != nil {
			panic(err)
		}
		return h
	}, 256 / 8
}
