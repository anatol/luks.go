package luks

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// LUKS v2 format is specified here
// https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/on-disk-format-luks2.pdf
type headerV2 struct {
	Magic             [6]byte
	Version           uint16
	HeaderSize        uint64
	SequenceID        uint64
	Label             [48]byte
	ChecksumAlgorithm [32]byte
	Salt              [64]byte
	UUID              [40]byte
	SubsystemLabel    [48]byte
	HeaderOffset      uint64
	_                 [184]byte // padding
	Checksum          [64]byte
	// padding of size 7*512
}

type deviceV2 struct {
	path  string
	hdrF  *os.File // header file: source of keyslot material
	dataF *os.File // data device: used for storage size; equals hdrF when header is embedded
	hdr   *headerV2
	meta  *metadata
	flags []string
}

func initV2Device(path string, hdrF, dataF *os.File) (*deviceV2, error) {
	var hdr headerV2

	if _, err := hdrF.Seek(0, 0); err != nil {
		return nil, err
	}
	if err := binary.Read(hdrF, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	// HeaderSize covers the binary header plus the JSON metadata area.
	// Per the LUKS2 spec it must be a power of two between 16 KiB and 4 MiB.
	hdrSize := hdr.HeaderSize
	if !isPowerOfTwo(uint(hdrSize)) || hdrSize < 16384 || hdrSize > 4194304 {
		return nil, fmt.Errorf("invalid size of LUKS header: %v", hdrSize)
	}

	// read the whole header
	data := make([]byte, hdrSize)
	if _, err := hdrF.ReadAt(data, 0); err != nil {
		return nil, err
	}

	// To verify header integrity, zero out the checksum field in the data copy
	// and compute a fresh checksum over the entire header area.
	for i := range 64 {
		data[int(unsafe.Offsetof(hdr.Checksum))+i] = 0
	}

	var h hash.Hash
	algo := fixedArrayToString(hdr.ChecksumAlgorithm[:])
	switch algo {
	case "sha256":
		h = sha256.New()
	default:
		return nil, fmt.Errorf("unknown header checksum algorithm: %v", algo)
	}

	h.Write(data)

	checksum := h.Sum(nil)
	expectedChecksum := hdr.Checksum[:h.Size()]
	if !bytes.Equal(checksum, expectedChecksum) {
		return nil, fmt.Errorf("invalid header checksum")
	}

	// The JSON metadata area starts at offset 4096 (after the 4 KiB binary header)
	var meta metadata
	jsonData := data[4096:]
	if end := bytes.IndexByte(jsonData, 0); end >= 0 {
		jsonData = jsonData[:end]
	}

	if err := json.Unmarshal(jsonData, &meta); err != nil {
		return nil, err
	}

	return &deviceV2{
		path:  path,
		hdrF:  hdrF,
		dataF: dataF,
		hdr:   &hdr,
		meta:  &meta,
		flags: meta.Config.Flags,
	}, nil
}

// Close implements Device.Close for LUKS v2 devices.
func (d *deviceV2) Close() error {
	err := d.hdrF.Close()
	if d.dataF != d.hdrF {
		if err2 := d.dataF.Close(); err == nil {
			err = err2
		}
	}
	return err
}

// Path implements Device.Path for LUKS v2 devices.
func (d *deviceV2) Path() string {
	return d.path
}

// Slots implements Device.Slots for LUKS v2 devices.
// Returns keyslot indices sorted by priority: high (2) first, then normal (1 or nil).
// Slots with priority 0 (ignore) are excluded.
func (d *deviceV2) Slots() []int {
	var normPrio, highPrio []int
	for i, k := range d.meta.Keyslots {
		if k.Priority != nil && *k.Priority == 2 {
			highPrio = append(highPrio, i)
		} else if k.Priority == nil || *k.Priority == 1 {
			normPrio = append(normPrio, i)
		}
		// priority 0 means "ignore": slot is skipped
	}
	return append(highPrio, normPrio...)
}

// Tokens implements Device.Tokens for LUKS v2 devices.
// Parses token entries from the JSON metadata, extracting type and associated keyslot IDs.
func (d *deviceV2) Tokens() ([]Token, error) {
	var tokens []Token

	type tokenNode struct {
		Type     string
		Keyslots []json.Number
	}

	for i, t := range d.meta.Tokens {
		var node tokenNode
		if err := json.Unmarshal(t, &node); err != nil {
			return nil, err
		}

		keyslots := make([]int, len(node.Keyslots))
		for j, s := range node.Keyslots {
			slotID, err := s.Int64()
			if err != nil {
				return nil, err
			}
			keyslots[j] = int(slotID)
		}

		token := Token{
			ID:      i,
			Slots:   keyslots,
			Type:    node.Type,
			Payload: t,
		}

		tokens = append(tokens, token)
	}

	return tokens, nil
}

// UUID implements Device.UUID for LUKS v2 devices.
func (d *deviceV2) UUID() string {
	return fixedArrayToString(d.hdr.UUID[:])
}

// FlagsGet implements Device.FlagsGet for LUKS v2 devices.
func (d *deviceV2) FlagsGet() []string {
	return d.flags
}

// FlagsAdd implements Device.FlagsAdd for LUKS v2 devices.
func (d *deviceV2) FlagsAdd(flags ...string) error {
	d.flags = append(d.flags, flags...)
	return nil
}

// FlagsClear implements Device.FlagsClear for LUKS v2 devices.
func (d *deviceV2) FlagsClear() {
	d.flags = nil
}

// Version implements Device.Version for LUKS v2 devices.
func (d *deviceV2) Version() int {
	return 2
}

// Unlock implements Device.Unlock for LUKS v2 devices.
func (d *deviceV2) Unlock(keyslot int, passphrase []byte, dmName string) error {
	volume, err := d.UnsealVolume(keyslot, passphrase)
	if err != nil {
		return err
	}
	defer volume.Clear()

	return volume.SetupMapper(dmName)
}

// UnlockAny implements Device.UnlockAny for LUKS v2 devices.
func (d *deviceV2) UnlockAny(passphrase []byte, dmName string) error {
	for _, s := range d.Slots() {
		volume, err := d.UnsealVolume(s, passphrase)
		if errors.Is(err, ErrPassphraseDoesNotMatch) {
			continue
		} else if err != nil {
			return err
		}
		defer volume.Clear()

		return volume.SetupMapper(dmName)
	}
	return ErrPassphraseDoesNotMatch
}

// supportedRequirements lists the LUKS2 mandatory requirements this library
// implements. A device carrying any other mandatory requirement must not be
// activated: the unknown feature may change how the data area is mapped
// (e.g. online reencryption), so proceeding could corrupt data.
var supportedRequirements = map[string]bool{
	"opal": true, // TCG OPAL hardware encryption (cryptsetup >= 2.7)
}

// checkRequirements refuses to proceed when the header carries a mandatory
// requirement this library does not implement. Enforced at unseal time rather
// than open time so that read-only introspection (Slots, Tokens, UUID) keeps
// working on such devices, mirroring cryptsetup's luksDump behavior.
func (d *deviceV2) checkRequirements() error {
	for _, r := range d.meta.Config.Requirements {
		if !supportedRequirements[r] {
			return fmt.Errorf("LUKS2 device has unsupported mandatory requirement %q", r)
		}
	}
	return nil
}

// UnsealVolume implements Device.UnsealVolume for LUKS v2 devices.
// It derives the anti-forensic key using the keyslot's KDF (PBKDF2 or Argon2),
// decrypts the keyslot area, recovers the volume key, and verifies it against
// the digest entry associated with this keyslot.
func (d *deviceV2) UnsealVolume(keyslotIdx int, passphrase []byte) (*Volume, error) {
	if err := d.checkRequirements(); err != nil {
		return nil, err
	}

	keyslots := d.meta.Keyslots

	keyslot, ok := keyslots[keyslotIdx]
	if !ok {
		return nil, fmt.Errorf("unable to get a keyslot with id: %d", keyslotIdx)
	}

	afKey, err := deriveLuks2AfKey(keyslot.Kdf, keyslotIdx, passphrase, keyslot.Area.KeySize)
	if err != nil {
		return nil, err
	}
	defer clearSlice(afKey)

	finalKey, err := d.decryptLuks2VolumeKey(keyslotIdx, keyslot, afKey)
	if err != nil {
		return nil, err
	}

	// verify with digest
	digest := d.findDigestForKeyslot(keyslotIdx)
	if digest == nil {
		return nil, fmt.Errorf("no digest is found for keyslot %v", keyslotIdx)
	}

	generatedDigest, err := computeDigestForKey(digest, keyslotIdx, finalKey)
	if err != nil {
		return nil, err
	}
	defer clearSlice(generatedDigest)

	expectedDigest, err := base64.StdEncoding.DecodeString(digest.Digest)
	if err != nil {
		return nil, fmt.Errorf("keyslotIdx[%v].digest.Digest base64 parsing failed: %v", keyslotIdx, err)
	}
	if !bytes.Equal(generatedDigest[0:len(expectedDigest)], expectedDigest) {
		return nil, ErrPassphraseDoesNotMatch
	}
	clearSlice(generatedDigest)

	storageSegment, err := d.findStorageSegment(digest)
	if err != nil {
		return nil, err
	}
	offset, err := storageSegment.Offset.Int64()
	if err != nil {
		return nil, err
	}

	// The segment size is a string: either "dynamic" (fill remaining device space)
	// or a decimal byte count. This follows the LUKS2 on-disk JSON format.
	var storageSize uint64
	if storageSegment.Size == "dynamic" {
		storageSize, err = fileSize(d.dataF)
		if err != nil {
			return nil, err
		}
		if storageSize < uint64(offset) {
			return nil, fmt.Errorf("backing file size %d is smaller than LUKS segment offset %d", storageSize, offset)
		}

		storageSize -= uint64(offset)
	} else {
		size, err := strconv.Atoi(storageSegment.Size)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, fmt.Errorf("invalid segment size: %v", size)
		}

		storageSize = uint64(size)
	}

	// pure "hw-opal" segments have no iv_tweak field
	var ivTweak int64
	if storageSegment.Type != "hw-opal" {
		ivTweak, err = storageSegment.IvTweak.Int64()
		if err != nil {
			return nil, err
		}
	}

	v := &Volume{
		BackingDevice:     d.path,
		Flags:             d.flags,
		UUID:              d.UUID(),
		key:               finalKey,
		LuksType:          "LUKS2",
		StorageSize:       storageSize,
		StorageOffset:     uint64(offset),
		StorageEncryption: storageSegment.Encryption,
		StorageIvTweak:    uint64(ivTweak),
		StorageSectorSize: uint64(storageSegment.SectorSize),
		segmentType:       storageSegment.Type,
	}

	if storageSegment.Type == "hw-opal" || storageSegment.Type == "hw-opal-crypt" {
		opal, err := parseOpalSegment(storageSegment, len(finalKey))
		if err != nil {
			return nil, err
		}
		// the dm UUID type cryptsetup uses for OPAL-backed devices; the
		// only OPAL marker available once a device is active
		v.LuksType = "LUKS2-OPAL"
		v.opalKeySize = opal.keySize
		v.opalSegmentNumber = opal.segmentNumber
		v.opalSegmentSize = opal.segmentSize
		if storageSegment.Type == "hw-opal" {
			// cryptsetup's default for segments without a sector_size field
			v.StorageSectorSize = 512
		}
	}

	return v, nil
}

func computeDigestForKey(dig *digest, keyslotIdx int, finalKey []byte) ([]byte, error) {
	digSalt, err := base64.StdEncoding.DecodeString(dig.Salt)
	if err != nil {
		return nil, fmt.Errorf("keyslotIdx[%v].digest.salt base64 parsing failed: %v", keyslotIdx, err)
	}

	switch dig.Type {
	case "pbkdf2":
		h, size := getHashAlgo(dig.Hash)
		if h == nil {
			return nil, fmt.Errorf("unknown digest hash algorithm: %v", dig.Hash)
		}
		return pbkdf2.Key(finalKey, digSalt, int(dig.Iterations), size, h), nil
	default:
		return nil, fmt.Errorf("unknown digest kdf type: %v", dig.Type)
	}
}

func (d *deviceV2) decryptLuks2VolumeKey(keyslotIdx int, keyslot keyslot, afKey []byte) ([]byte, error) {
	// this method follows logic at luks2_keyslot_get_key()
	area := keyslot.Area

	// decrypt keyslotIdx area using the derived key
	keyslotSize := keyslot.KeySize * stripesNum

	areaSize, err := area.Size.Int64()
	if err != nil {
		return nil, fmt.Errorf("Invalid keyslotIdx[%v] size value: %v. %v", keyslotIdx, area.Size, err)
	}
	if int64(keyslotSize) > areaSize {
		return nil, fmt.Errorf("keyslot[%v] area size too small, given %v expected at least %v", keyslotIdx, areaSize, keyslotSize)
	}
	if keyslotSize%storageSectorSize != 0 {
		return nil, fmt.Errorf("keyslot[%v] size %v is not multiple of the sector size %v", keyslotIdx, keyslotSize, storageSectorSize)
	}

	keyData := make([]byte, keyslotSize)
	defer clearSlice(keyData)

	keyslotOffset, err := area.Offset.Int64()
	if err != nil {
		return nil, fmt.Errorf("Invalid keyslotIdx[%v] offset: %v. %v", keyslotIdx, area.Offset, err)
	}
	if keyslotOffset%storageSectorSize != 0 {
		return nil, fmt.Errorf("keyslot[%v] offset %v is not aligned to sector size %v", keyslotIdx, keyslotOffset, storageSectorSize)
	}

	if _, err := d.hdrF.ReadAt(keyData, keyslotOffset); err != nil {
		return nil, err
	}

	ciph, err := buildLuks2AfCipher(area.Encryption, afKey)
	if err != nil {
		return nil, err
	}

	// XTS decryption operates sector-by-sector, using the sector index as the tweak
	for i := 0; i < int(keyslotSize/storageSectorSize); i++ {
		block := keyData[i*storageSectorSize : (i+1)*storageSectorSize]
		ciph.Decrypt(block, block, uint64(i))
	}

	// Recover the volume key from the anti-forensic split format.
	// LUKS requires exactly 4000 stripes per the specification.
	af := keyslot.Af
	if af.Stripes != stripesNum {
		return nil, fmt.Errorf("LUKS currently supports only AF with 4000 stripes")
	}
	h, _ := getHashAlgo(af.Hash)
	if h == nil {
		return nil, fmt.Errorf("unknown AF hash algorithm: %v", af.Hash)
	}

	return afMerge(keyData, int(keyslot.KeySize), int(af.Stripes), h())
}

func buildLuks2AfCipher(encryption string, afKey []byte) (*xts.Cipher, error) {
	// parse encryption mode for the keyslot area, see crypt_parse_name_and_mode()
	// example of `encryption` value is 'aes-xts-plain64'
	encParts := strings.Split(encryption, "-")
	if len(encParts) != 3 {
		return nil, fmt.Errorf("unexpected encryption format: %v", encryption)
	}
	cipherName := encParts[0]
	cipherMode := encParts[1]
	// ivModeName := encParts[2]

	cipherFunc, err := getCipher(cipherName)
	if err != nil {
		return nil, err
	}

	switch cipherMode {
	case "xts":
		return xts.NewCipher(cipherFunc, afKey)
	default:
		return nil, fmt.Errorf("unknown encryption mode: %v", cipherMode)
	}
}

func deriveLuks2AfKey(kdf kdf, keyslotIdx int, passphrase []byte, keyLength uint) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(kdf.Salt)
	if err != nil {
		return nil, fmt.Errorf("keyslotIdx[%v].kdf.salt base64 parsing failed: %v", keyslotIdx, err)
	}

	switch kdf.Type {
	case "pbkdf2":
		h, _ := getHashAlgo(kdf.Hash)
		if h == nil {
			return nil, fmt.Errorf("unknown keyslot[%v] kdf hash algorithm: %v", keyslotIdx, kdf.Hash)
		}
		return pbkdf2.Key(passphrase, salt, int(kdf.Iterations), int(keyLength), h), nil
	case "argon2i":
		return argon2.Key(passphrase, salt, uint32(kdf.Time), uint32(kdf.Memory), uint8(kdf.Cpus), uint32(keyLength)), nil
	case "argon2id":
		return argon2.IDKey(passphrase, salt, uint32(kdf.Time), uint32(kdf.Memory), uint8(kdf.Cpus), uint32(keyLength)), nil
	default:
		return nil, fmt.Errorf("unknown kdf type: %v", kdf.Type)
	}
}

// findDigestForKeyslot searches the metadata digests for one that references the given keyslot.
func (d *deviceV2) findDigestForKeyslot(keyslotIdx int) *digest {
	for _, dig := range d.meta.Digests {
		for _, k := range dig.Keyslots {
			k, e := k.Int64()
			if e != nil {
				continue
			}
			if int(k) == keyslotIdx {
				return &dig
			}
		}
	}
	return nil
}

// storageSegmentTypes are the segment types this library can activate:
// software dm-crypt ("crypt") and the TCG OPAL hardware-encryption types
// introduced by cryptsetup 2.7.
var storageSegmentTypes = map[string]bool{
	"crypt":         true,
	"hw-opal":       true,
	"hw-opal-crypt": true,
}

// findStorageSegment returns the first activatable storage segment referenced
// by the given digest. This handles the multi-segment case (e.g. integrity
// layouts) where a digest may cover both a storage and a "linear" segment.
func (d *deviceV2) findStorageSegment(dig *digest) (*segment, error) {
	for _, segNum := range dig.Segments {
		segID, err := segNum.Int64()
		if err != nil {
			continue
		}
		seg, ok := d.meta.Segments[int(segID)]
		if !ok {
			continue
		}
		if storageSegmentTypes[seg.Type] {
			return &seg, nil
		}
	}
	return nil, fmt.Errorf("no storage segment found in digest (segments: %v)", dig.Segments)
}
