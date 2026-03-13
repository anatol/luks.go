package luks

// format.go implements FormatV1 and FormatV2 — creating new LUKS volumes from scratch.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// generateUUID generates a random RFC-4122 v4 UUID string.
func generateUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits (RFC 4122)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// copyStringToFixed copies s into a fixed-size byte array (null-terminated, zero-padded).
func copyStringToFixed(dst []byte, s string) {
	for i := range dst {
		dst[i] = 0
	}
	copy(dst, s)
}

// ----------------------------------------------------------------------------
// FormatV1
// ----------------------------------------------------------------------------

// FormatV1 writes a LUKS v1 header with one active keyslot to an existing file
// or block device at path.  The device must already exist and be large enough to
// hold the header + at least a few sectors of data.
// Returns an open Device on success; the caller is responsible for closing it.
func FormatV1(path string, passphrase []byte, opts *FormatV1Options) (Device, error) {
	// Apply defaults.
	if opts == nil {
		opts = &FormatV1Options{}
	}
	if opts.Cipher == "" {
		opts.Cipher = "aes"
	}
	if opts.CipherMode == "" {
		opts.CipherMode = "xts-plain64"
	}
	if opts.Hash == "" {
		opts.Hash = "sha256"
	}
	if opts.MasterKeySize == 0 {
		opts.MasterKeySize = 32 // 256-bit key (AES-128-XTS)
	}
	if opts.Iter == 0 {
		opts.Iter = 100_000 // reasonable default; real calibration is future work
	}
	if opts.UUID == "" {
		var err error
		opts.UUID, err = generateUUID()
		if err != nil {
			return nil, err
		}
	}

	h, _ := getHashAlgo(opts.Hash)
	if h == nil {
		return nil, fmt.Errorf("unknown hash algorithm: %s", opts.Hash)
	}
	if _, err := getCipher(opts.Cipher); err != nil {
		return nil, err
	}

	// Generate random master key.
	masterKey := make([]byte, opts.MasterKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, err
	}
	defer clearSlice(masterKey)

	// Generate MK digest salt and compute digest (PBKDF2 truncated to 20 bytes).
	var mkDigestSalt [32]byte
	if _, err := rand.Read(mkDigestSalt[:]); err != nil {
		return nil, err
	}
	const mkDigestIter = 10 // intentionally low; this is the anti-forensic digest, not KDF
	digestFull := pbkdf2.Key(masterKey, mkDigestSalt[:], mkDigestIter, opts.MasterKeySize, h)
	defer clearSlice(digestFull)
	var mkDigest [20]byte
	copy(mkDigest[:], digestFull[:20])

	// Build keyslot 0.
	var salt0 [32]byte
	if _, err := rand.Read(salt0[:]); err != nil {
		return nil, err
	}

	keyBytes := uint32(opts.MasterKeySize)
	ks0 := keySlot{
		Active:            luksV1SlotEnabled,
		Iterations:        uint32(opts.Iter),
		Salt:              salt0,
		KeyMaterialOffset: luksV1KeyslotOffset(0, keyBytes),
		Stripes:           stripesNum,
	}

	// Build the full header.
	var hdr headerV1
	copy(hdr.Magic[:], []byte("LUKS\xba\xbe"))
	hdr.Version = 1
	copyStringToFixed(hdr.CipherName[:], opts.Cipher)
	copyStringToFixed(hdr.CipherMode[:], opts.CipherMode)
	copyStringToFixed(hdr.HashSpec[:], opts.Hash)
	hdr.PayloadOffset = luksV1PayloadOffset(keyBytes)
	hdr.KeyBytes = keyBytes
	hdr.MkDigest = mkDigest
	hdr.MkDigestSalt = mkDigestSalt
	hdr.MkDigestIter = mkDigestIter
	copyStringToFixed(hdr.UUID[:], opts.UUID)
	// Initialize all keyslots to disabled state (cryptsetup requires valid stripes+offset even for disabled slots).
	for i := range hdr.KeySlots {
		hdr.KeySlots[i] = keySlot{
			Active:            luksV1SlotDisabled,
			KeyMaterialOffset: luksV1KeyslotOffset(i, keyBytes),
			Stripes:           stripesNum,
		}
	}
	hdr.KeySlots[0] = ks0

	// Open file for writing.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	// Write keyslot 0 material.
	if err := encryptKeyMaterialV1(f, &hdr, 0, masterKey, passphrase, h); err != nil {
		f.Close()
		return nil, err
	}

	// Write header at offset 0.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	if err := binary.Write(f, binary.BigEndian, &hdr); err != nil {
		f.Close()
		return nil, err
	}

	// Reopen as a proper Device (read-only handle is fine for the device object).
	f.Close()
	return Open(path)
}

// ----------------------------------------------------------------------------
// FormatV2
// ----------------------------------------------------------------------------

// FormatV2 writes a LUKS v2 header with one active keyslot to an existing file
// or block device at path.
// Returns an open Device on success; the caller is responsible for closing it.
func FormatV2(path string, passphrase []byte, opts *FormatV2Options) (Device, error) {
	// Apply defaults.
	if opts == nil {
		opts = &FormatV2Options{}
	}
	if opts.Cipher == "" {
		opts.Cipher = "aes"
	}
	if opts.CipherMode == "" {
		opts.CipherMode = "xts-plain64"
	}
	if opts.SectorSize == 0 {
		opts.SectorSize = 512
	}
	if opts.MasterKeySize == 0 {
		opts.MasterKeySize = 64 // 512-bit key (AES-256-XTS)
	}
	if opts.KDFType == "" {
		opts.KDFType = "argon2id"
	}
	if opts.KDFHash == "" {
		opts.KDFHash = "sha256"
	}
	if opts.KDFType == "argon2id" || opts.KDFType == "argon2i" {
		if opts.KDFTime == 0 {
			opts.KDFTime = 4
		}
		if opts.KDFMemory == 0 {
			opts.KDFMemory = 1048576
		}
		if opts.KDFCPUs == 0 {
			opts.KDFCPUs = 4
		}
	}
	if opts.KDFType == "pbkdf2" && opts.KDFIter == 0 {
		opts.KDFIter = 100_000
	}
	if opts.UUID == "" {
		var err error
		opts.UUID, err = generateUUID()
		if err != nil {
			return nil, err
		}
	}

	encryption := opts.Cipher + "-" + opts.CipherMode

	// Validate cipher.
	if _, err := getCipher(opts.Cipher); err != nil {
		return nil, err
	}
	digestHash, digestHashSize := getHashAlgo(opts.KDFHash)
	if digestHash == nil {
		return nil, fmt.Errorf("unknown hash algorithm: %s", opts.KDFHash)
	}

	// Generate master key.
	masterKey := make([]byte, opts.MasterKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, err
	}
	defer clearSlice(masterKey)

	// Generate keyslot 0 KDF salt and derive AF key.
	kdfSalt := make([]byte, 32)
	if _, err := rand.Read(kdfSalt); err != nil {
		return nil, err
	}
	kdfSaltB64 := base64.StdEncoding.EncodeToString(kdfSalt)

	afKey, err := deriveV2AfKey(opts.KDFType, opts.KDFHash, kdfSaltB64, opts.KDFIter, opts.KDFTime, opts.KDFMemory, opts.KDFCPUs, passphrase, opts.MasterKeySize)
	if err != nil {
		return nil, err
	}
	defer clearSlice(afKey)

	// Compute keyslot area dimensions.
	keySize := opts.MasterKeySize
	rawAreaSize := int64(keySize * stripesNum)
	areaSize := (rawAreaSize + 4095) &^ 4095
	areaOffset := int64(luks2KeyslotAreaStart)

	// Compute the volume-key digest (PBKDF2).
	digestSalt := make([]byte, 32)
	if _, err := rand.Read(digestSalt); err != nil {
		return nil, err
	}
	digestValue := pbkdf2.Key(masterKey, digestSalt, luks2DigestIter, digestHashSize, digestHash)
	defer clearSlice(digestValue)

	// Build metadata.
	meta := &metadata{
		Keyslots: map[int]keyslot{
			0: {
				Type:    "luks2",
				KeySize: uint(keySize),
				Af: antiForensic{
					Type:    "luks1",
					Stripes: stripesNum,
					Hash:    opts.KDFHash,
				},
				Area: area{
					Type:       "raw",
					Encryption: encryption,
					KeySize:    uint(keySize),
					Offset:     jsonNumStr(strconv.FormatInt(areaOffset, 10)),
					Size:       jsonNumStr(strconv.FormatInt(areaSize, 10)),
				},
				Kdf: buildKdf(opts.KDFType, opts.KDFHash, kdfSaltB64, opts.KDFIter, opts.KDFTime, opts.KDFMemory, opts.KDFCPUs),
			},
		},
		Tokens: map[int]json.RawMessage{},
		Segments: map[int]segment{
			0: {
				Type:       "crypt",
				Offset:     jsonNumStr(strconv.Itoa(luks2DataSegmentOffset)),
				IvTweak:    jsonNumStr("0"),
				Size:       "dynamic",
				Encryption: encryption,
				SectorSize: uint(opts.SectorSize),
			},
		},
		Digests: map[int]digest{
			0: {
				Type:       "pbkdf2",
				Keyslots:   []string{"0"},
				Segments:   []string{"0"},
				Hash:       opts.KDFHash,
				Iterations: luks2DigestIter,
				Salt:       base64.StdEncoding.EncodeToString(digestSalt),
				Digest:     base64.StdEncoding.EncodeToString(digestValue),
			},
		},
		Config: config{
			JSONSize:     jsonNumStr(strconv.Itoa(luks2JSONSize)),
			KeyslotsSize: jsonNumStr(strconv.Itoa(luks2KeyslotsSize)),
		},
	}

	// Build the binary header (SequenceID starts at 1 for a fresh device; writeV2Headers increments it,
	// so we start at 0 to end up at 1 after writing).
	var hdr headerV2
	copy(hdr.Magic[:], []byte("LUKS\xba\xbe"))
	hdr.Version = 2
	hdr.HeaderSize = uint64(luks2HeaderSize)
	hdr.SequenceID = 0 // will become 1 after writeV2Headers increments
	copyStringToFixed(hdr.Label[:], opts.Label)
	copyStringToFixed(hdr.ChecksumAlgorithm[:], "sha256")
	copyStringToFixed(hdr.UUID[:], opts.UUID)
	// hdr.SubsystemLabel left as zeros
	// hdr.HeaderOffset and hdr.Salt are filled by writeSingleV2Header

	// Open file for writing.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	// Write keyslot 0 material.
	hashFn, _ := getHashAlgo(opts.KDFHash)
	if err := encryptKeyMaterialV2(f, encryption, afKey, masterKey, keySize, areaOffset, hashFn); err != nil {
		f.Close()
		return nil, err
	}

	// Write both header copies.
	if err := writeV2Headers(f, &hdr, meta); err != nil {
		f.Close()
		return nil, err
	}

	f.Close()
	return Open(path)
}
