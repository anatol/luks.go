package luks

// luks2_write.go implements write operations for LUKS v2 devices.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// LUKS2 on-disk layout constants.
// These match cryptsetup defaults for compatibility.
const (
	// luks2BinaryHeaderSize is the total on-disk size of one binary header copy (4 KiB).
	// The headerV2 struct is 512 bytes; the remaining 3584 bytes are implicit zeros on disk.
	luks2BinaryHeaderSize = 4096

	// luks2JSONSize is the JSON metadata area size per header copy (12 KiB).
	luks2JSONSize = 12288

	// luks2HeaderSize is hdr.HeaderSize = binary header + JSON = 16 KiB per copy.
	luks2HeaderSize = luks2BinaryHeaderSize + luks2JSONSize // 16384

	// luks2KeyslotAreaStart is the byte offset where keyslot material begins.
	// This follows both header copies: 2 × luks2HeaderSize = 32768.
	luks2KeyslotAreaStart = luks2HeaderSize * 2 // 32768

	// luks2DataSegmentOffset is the default offset for the data segment (16 MiB).
	// This provides ample room for keyslot material.
	luks2DataSegmentOffset = 16 * 1024 * 1024 // 16777216

	// luks2KeyslotsSize is the total keyslot material area size.
	luks2KeyslotsSize = luks2DataSegmentOffset - luks2KeyslotAreaStart // 16744448

	// luks2DigestIter is the PBKDF2 iteration count used for the volume key digest.
	luks2DigestIter = 197608
)

// openHdrRW opens the LUKS v2 header file for read-write access.
func (d *deviceV2) openHdrRW() (*os.File, error) {
	return os.OpenFile(d.hdrF.Name(), os.O_RDWR, 0)
}

// flushMetadata serialises d.meta to JSON, increments SequenceID, recomputes
// checksums for both binary header copies, and writes them to disk.
func (d *deviceV2) flushMetadata() error {
	f, err := d.openHdrRW()
	if err != nil {
		return err
	}
	defer f.Close()
	return writeV2Headers(f, d.hdr, d.meta)
}

// writeV2Headers writes both primary and secondary LUKS2 header copies.
// It increments hdr.SequenceID and computes the checksum for each copy.
func writeV2Headers(f *os.File, hdr *headerV2, meta *metadata) error {
	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if len(jsonBytes) > luks2JSONSize {
		return fmt.Errorf("JSON metadata (%d bytes) exceeds json_size (%d bytes)", len(jsonBytes), luks2JSONSize)
	}
	// Pad JSON to exactly luks2JSONSize with zeros.
	jsonPadded := make([]byte, luks2JSONSize)
	copy(jsonPadded, jsonBytes)

	hdr.SequenceID++

	// Primary copy at offset 0.
	hdr.HeaderOffset = 0
	if err := writeSingleV2Header(f, hdr, jsonPadded, 0); err != nil {
		return fmt.Errorf("write primary header: %w", err)
	}

	// Secondary copy at offset luks2HeaderSize.
	hdr.HeaderOffset = uint64(luks2HeaderSize)
	if err := writeSingleV2Header(f, hdr, jsonPadded, int64(luks2HeaderSize)); err != nil {
		return fmt.Errorf("write secondary header: %w", err)
	}

	return nil
}

// writeSingleV2Header writes one binary header + JSON block at fileOffset.
// It generates a fresh random Salt for this copy and recomputes the checksum.
// The checksum covers the entire luks2HeaderSize (4096 + 12288 = 16384 bytes),
// which matches what initV2Device verifies during reading.
func writeSingleV2Header(f *os.File, hdr *headerV2, jsonPadded []byte, fileOffset int64) error {
	// Generate fresh random salt for this header copy.
	if _, err := rand.Read(hdr.Salt[:]); err != nil {
		return err
	}

	// Build the 4096-byte binary header block.
	// The headerV2 struct is 512 bytes; the remaining 3584 bytes are zeros.
	headerBlock := make([]byte, luks2BinaryHeaderSize)
	clearSlice(hdr.Checksum[:]) // zero checksum before computing it

	w := &byteSliceWriter{b: headerBlock}
	if err := binary.Write(w, binary.BigEndian, hdr); err != nil {
		return fmt.Errorf("serialise header struct: %w", err)
	}
	// bytes 512..4095 remain zero (implicit padding)

	// Compute checksum over [binary header block (4096 bytes)] + [JSON (12288 bytes)].
	h := sha256.New()
	h.Write(headerBlock)
	h.Write(jsonPadded)
	checksum := h.Sum(nil)

	// Write checksum into the header block and update the in-memory struct.
	checksumOffset := int(unsafe.Offsetof(hdr.Checksum))
	copy(headerBlock[checksumOffset:], checksum)
	copy(hdr.Checksum[:], checksum)

	// Write the 4096-byte binary header.
	if _, err := f.WriteAt(headerBlock, fileOffset); err != nil {
		return fmt.Errorf("write binary header at %d: %w", fileOffset, err)
	}
	// Write the JSON immediately after the binary header.
	if _, err := f.WriteAt(jsonPadded, fileOffset+luks2BinaryHeaderSize); err != nil {
		return fmt.Errorf("write JSON at %d: %w", fileOffset+luks2BinaryHeaderSize, err)
	}
	return nil
}

// byteSliceWriter is an io.Writer backed by a fixed byte slice.
type byteSliceWriter struct {
	b   []byte
	pos int
}

func (w *byteSliceWriter) Write(p []byte) (int, error) {
	n := copy(w.b[w.pos:], p)
	w.pos += n
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// nextFreeSlotV2 returns the lowest available slot ID, or a specific one if preferred >= 0.
func (d *deviceV2) nextFreeSlotV2(preferred int) (int, error) {
	if preferred >= 0 {
		if _, exists := d.meta.Keyslots[preferred]; exists {
			return 0, fmt.Errorf("keyslot %d is already in use", preferred)
		}
		return preferred, nil
	}
	for i := 0; i < 32; i++ {
		if _, exists := d.meta.Keyslots[i]; !exists {
			return i, nil
		}
	}
	return 0, fmt.Errorf("no free keyslot available (maximum 32 keyslots)")
}

// nextKeyslotAreaOffsetV2 returns a 4096-aligned byte offset for new keyslot material,
// placed after all existing areas. It skips over the secondary header region.
func (d *deviceV2) nextKeyslotAreaOffsetV2(areaSize int64) (int64, error) {
	offset := int64(luks2KeyslotAreaStart)
	for _, ks := range d.meta.Keyslots {
		start, err := ks.Area.Offset.Int64()
		if err != nil {
			continue
		}
		sz, err := ks.Area.Size.Int64()
		if err != nil {
			continue
		}
		if start+sz > offset {
			offset = start + sz
		}
	}
	// Align to 4096.
	offset = (offset + 4095) &^ 4095

	// Skip over the secondary header region [luks2HeaderSize, luks2HeaderSize*2).
	secStart := int64(luks2HeaderSize)
	secEnd := int64(luks2HeaderSize * 2)
	if offset < secEnd && offset+areaSize > secStart {
		offset = (secEnd + 4095) &^ 4095
	}

	// Must fit within the keyslot region [0, luks2DataSegmentOffset).
	if offset+areaSize > luks2DataSegmentOffset {
		return 0, fmt.Errorf("insufficient keyslot space: need %d bytes at %d, limit %d",
			areaSize, offset, luks2DataSegmentOffset)
	}
	return offset, nil
}

// buildKdf constructs a kdf struct with only the fields relevant to the given kdfType,
// ensuring that pbkdf2-specific and argon2-specific fields are not mixed.
func buildKdf(kdfType, kdfHash, saltB64 string, kdfIter int, kdfTime, kdfMemory uint32, kdfCPUs uint8) kdf {
	k := kdf{Type: kdfType, Salt: saltB64}
	switch kdfType {
	case "pbkdf2":
		k.Hash = kdfHash
		k.Iterations = uint(kdfIter)
	case "argon2i", "argon2id":
		k.Time = uint(kdfTime)
		k.Memory = uint(kdfMemory)
		k.Cpus = uint(kdfCPUs)
	}
	return k
}

// deriveV2AfKey derives the keyslot AF key from passphrase using the given KDF parameters.
func deriveV2AfKey(kdfType, kdfHash, saltB64 string, kdfIter int, kdfTime, kdfMemory uint32, kdfCPUs uint8, passphrase []byte, keyLen int) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("decode kdf salt: %w", err)
	}
	switch kdfType {
	case "pbkdf2":
		h, _ := getHashAlgo(kdfHash)
		if h == nil {
			return nil, fmt.Errorf("unknown kdf hash: %s", kdfHash)
		}
		return pbkdf2.Key(passphrase, salt, kdfIter, keyLen, h), nil
	case "argon2i":
		return argon2.Key(passphrase, salt, kdfTime, kdfMemory, kdfCPUs, uint32(keyLen)), nil
	case "argon2id":
		return argon2.IDKey(passphrase, salt, kdfTime, kdfMemory, kdfCPUs, uint32(keyLen)), nil
	default:
		return nil, fmt.Errorf("unknown kdf type: %s", kdfType)
	}
}

// encryptKeyMaterialV2 AF-splits and encrypts masterKey, writes the result at areaOffset.
func encryptKeyMaterialV2(f *os.File, encryption string, afKey, masterKey []byte, keySize int, areaOffset int64, h func() hash.Hash) error {
	splitKey, err := afSplit(masterKey, stripesNum, h())
	if err != nil {
		return fmt.Errorf("afSplit: %w", err)
	}
	defer clearSlice(splitKey)

	ciph, err := buildLuks2AfCipher(encryption, afKey)
	if err != nil {
		return err
	}

	keyslotSize := keySize * stripesNum
	for i := 0; i < keyslotSize/storageSectorSize; i++ {
		block := splitKey[i*storageSectorSize : (i+1)*storageSectorSize]
		ciph.Encrypt(block, block, uint64(i))
	}

	if _, err := f.WriteAt(splitKey, areaOffset); err != nil {
		return fmt.Errorf("write keyslot material: %w", err)
	}
	return nil
}

// recoverMasterKeyV2 tries all active keyslots and returns the master key + matched slot.
func (d *deviceV2) recoverMasterKeyV2(passphrase []byte) (masterKey []byte, slotIdx int, err error) {
	for _, s := range d.Slots() {
		v, e := d.UnsealVolume(s, passphrase)
		if e == nil {
			key := v.key
			v.key = nil
			return key, s, nil
		}
	}
	return nil, -1, ErrPassphraseDoesNotMatch
}

// defaultKDFParamsV2 returns default KDF parameters for a new keyslot,
// inheriting from existing slot 0 if available, otherwise using standard defaults.
func (d *deviceV2) defaultKDFParamsV2(masterKeyLen int) (kdfType, kdfHash, encryption string, keySize, kdfIter int, kdfTime, kdfMemory uint32, kdfCPUs uint8) {
	kdfType = "argon2id"
	kdfHash = "sha256"
	kdfIter = 100_000
	kdfTime = 4
	kdfMemory = 1048576
	kdfCPUs = uint8(runtime.NumCPU())
	if kdfCPUs > 4 {
		kdfCPUs = 4
	}
	encryption = "aes-xts-plain64"
	keySize = masterKeyLen

	if ref, ok := d.meta.Keyslots[0]; ok {
		kdfType = ref.Kdf.Type
		if ref.Kdf.Hash != "" {
			kdfHash = ref.Kdf.Hash
		}
		if ref.Kdf.Time > 0 {
			kdfTime = uint32(ref.Kdf.Time)
		}
		if ref.Kdf.Memory > 0 {
			kdfMemory = uint32(ref.Kdf.Memory)
		}
		if ref.Kdf.Cpus > 0 {
			kdfCPUs = uint8(ref.Kdf.Cpus)
		}
		if ref.Kdf.Iterations > 0 {
			kdfIter = int(ref.Kdf.Iterations)
		}
		if ref.Area.Encryption != "" {
			encryption = ref.Area.Encryption
		}
		keySize = int(ref.KeySize)
	}
	return
}

// addKeyToSlotV2 implements AddKey / AddKeyToSlot for LUKS v2.
func (d *deviceV2) addKeyToSlotV2(slotIdx int, existingPassphrase, newPassphrase []byte) (int, error) {
	masterKey, _, err := d.recoverMasterKeyV2(existingPassphrase)
	if err != nil {
		return 0, err
	}
	defer clearSlice(masterKey)

	newSlotID, err := d.nextFreeSlotV2(slotIdx)
	if err != nil {
		return 0, err
	}

	kdfType, kdfHash, encryption, keySize, kdfIter, kdfTime, kdfMemory, kdfCPUs := d.defaultKDFParamsV2(len(masterKey))

	saltBytes := make([]byte, 32)
	if _, err := rand.Read(saltBytes); err != nil {
		return 0, err
	}
	saltB64 := base64.StdEncoding.EncodeToString(saltBytes)

	afKey, err := deriveV2AfKey(kdfType, kdfHash, saltB64, kdfIter, kdfTime, kdfMemory, kdfCPUs, newPassphrase, keySize)
	if err != nil {
		return 0, err
	}
	defer clearSlice(afKey)

	rawAreaSize := int64(keySize * stripesNum)
	areaSize := (rawAreaSize + 4095) &^ 4095
	areaOffset, err := d.nextKeyslotAreaOffsetV2(areaSize)
	if err != nil {
		return 0, err
	}

	h, _ := getHashAlgo(kdfHash)
	if h == nil {
		return 0, fmt.Errorf("unknown af hash: %s", kdfHash)
	}

	f, err := d.openHdrRW()
	if err != nil {
		return 0, err
	}
	defer f.Close()

	if err := encryptKeyMaterialV2(f, encryption, afKey, masterKey, keySize, areaOffset, h); err != nil {
		return 0, err
	}

	newSlot := keyslot{
		Type:    "luks2",
		KeySize: uint(keySize),
		Af: antiForensic{
			Type:    "luks1",
			Stripes: stripesNum,
			Hash:    kdfHash,
		},
		Area: area{
			Type:       "raw",
			Encryption: encryption,
			KeySize:    uint(keySize),
			Offset:     jsonNumStr(strconv.FormatInt(areaOffset, 10)),
			Size:       jsonNumStr(strconv.FormatInt(areaSize, 10)),
		},
		Kdf: buildKdf(kdfType, kdfHash, saltB64, kdfIter, kdfTime, kdfMemory, kdfCPUs),
	}
	if d.meta.Keyslots == nil {
		d.meta.Keyslots = make(map[int]keyslot)
	}
	d.meta.Keyslots[newSlotID] = newSlot

	// Register new slot in digest 0.
	if dig, ok := d.meta.Digests[0]; ok {
		dig.Keyslots = append(dig.Keyslots, strconv.Itoa(newSlotID))
		d.meta.Digests[0] = dig
	}

	if err := writeV2Headers(f, d.hdr, d.meta); err != nil {
		return 0, err
	}
	return newSlotID, nil
}

// killSlotV2Core wipes the keyslot material and removes it from metadata.
// It does NOT check passphrases — callers must ensure safety.
func (d *deviceV2) killSlotV2Core(f *os.File, slotIdx int) error {
	ks, ok := d.meta.Keyslots[slotIdx]
	if !ok {
		return fmt.Errorf("keyslot %d is not active", slotIdx)
	}

	areaOffset, err := ks.Area.Offset.Int64()
	if err != nil {
		return err
	}
	areaSize, err := ks.Area.Size.Int64()
	if err != nil {
		return err
	}

	// Overwrite key material with random bytes.
	random := make([]byte, areaSize)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	if _, err := f.WriteAt(random, areaOffset); err != nil {
		return fmt.Errorf("wipe keyslot area: %w", err)
	}

	// Remove from metadata.
	delete(d.meta.Keyslots, slotIdx)
	for id, dig := range d.meta.Digests {
		filtered := dig.Keyslots[:0]
		for _, kStr := range dig.Keyslots {
			ki, _ := strconv.Atoi(kStr)
			if ki != slotIdx {
				filtered = append(filtered, kStr)
			}
		}
		dig.Keyslots = filtered
		d.meta.Digests[id] = dig
	}

	return writeV2Headers(f, d.hdr, d.meta)
}

// killSlotV2 implements KillSlot for LUKS v2.
// passphrase must match a *different* active keyslot.
func (d *deviceV2) killSlotV2(slotIdx int, passphrase []byte) error {
	if _, ok := d.meta.Keyslots[slotIdx]; !ok {
		return fmt.Errorf("keyslot %d is not active", slotIdx)
	}
	found := false
	for _, i := range d.Slots() {
		if i == slotIdx {
			continue
		}
		if _, err := d.UnsealVolume(i, passphrase); err == nil {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("passphrase does not match any other active keyslot; refusing to destroy last access")
	}

	f, err := d.openHdrRW()
	if err != nil {
		return err
	}
	defer f.Close()
	return d.killSlotV2Core(f, slotIdx)
}

// removeKeyV2 implements RemoveKey for LUKS v2.
func (d *deviceV2) removeKeyV2(passphrase []byte) error {
	_, matchedSlot, err := d.recoverMasterKeyV2(passphrase)
	if err != nil {
		return err
	}

	slots := d.Slots()
	if len(slots) == 1 {
		return fmt.Errorf("refusing to remove the last active keyslot")
	}

	f, err := d.openHdrRW()
	if err != nil {
		return err
	}
	defer f.Close()
	return d.killSlotV2Core(f, matchedSlot)
}

// changeKeyV2 implements ChangeKey for LUKS v2.
func (d *deviceV2) changeKeyV2(existingPassphrase, newPassphrase []byte) error {
	masterKey, matchedSlot, err := d.recoverMasterKeyV2(existingPassphrase)
	if err != nil {
		return err
	}
	defer clearSlice(masterKey)

	if len(d.Slots()) > 1 {
		// Safe swap: add new key first, then kill old slot.
		newSlotID, err := d.addKeyToSlotV2(-1, existingPassphrase, newPassphrase)
		if err != nil {
			return fmt.Errorf("add new key: %w", err)
		}
		_ = newSlotID
		return d.killSlotV2(matchedSlot, newPassphrase)
	}

	// Single slot: overwrite in place with new passphrase.
	ks := d.meta.Keyslots[matchedSlot]
	kdfType := ks.Kdf.Type
	kdfHash := ks.Kdf.Hash
	kdfIter := int(ks.Kdf.Iterations)
	kdfTime := uint32(ks.Kdf.Time)
	kdfMemory := uint32(ks.Kdf.Memory)
	kdfCPUs := uint8(ks.Kdf.Cpus)
	keySize := int(ks.KeySize)
	encryption := ks.Area.Encryption

	saltBytes := make([]byte, 32)
	if _, err := rand.Read(saltBytes); err != nil {
		return err
	}
	saltB64 := base64.StdEncoding.EncodeToString(saltBytes)

	afKey, err := deriveV2AfKey(kdfType, kdfHash, saltB64, kdfIter, kdfTime, kdfMemory, kdfCPUs, newPassphrase, keySize)
	if err != nil {
		return err
	}
	defer clearSlice(afKey)

	h, _ := getHashAlgo(ks.Af.Hash)
	if h == nil {
		return fmt.Errorf("unknown af hash: %s", ks.Af.Hash)
	}

	areaOffset, err := ks.Area.Offset.Int64()
	if err != nil {
		return err
	}

	f, err := d.openHdrRW()
	if err != nil {
		return err
	}
	defer f.Close()

	if err := encryptKeyMaterialV2(f, encryption, afKey, masterKey, keySize, areaOffset, h); err != nil {
		return err
	}

	ks.Kdf.Salt = saltB64
	d.meta.Keyslots[matchedSlot] = ks

	return writeV2Headers(f, d.hdr, d.meta)
}

// headerBackupV2 implements HeaderBackup for LUKS v2.
func (d *deviceV2) headerBackupV2(path string) error {
	// The backup includes both header copies + keyslot area up to data segment start.
	backupSize := int64(luks2DataSegmentOffset)
	buf := make([]byte, backupSize)
	if _, err := d.hdrF.ReadAt(buf, 0); err != nil && err != io.EOF {
		return fmt.Errorf("read header region: %w", err)
	}
	return os.WriteFile(path, buf, 0600)
}

// headerRestoreV2 implements HeaderRestore for LUKS v2.
func (d *deviceV2) headerRestoreV2(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f, err := d.openHdrRW()
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt(buf, 0); err != nil {
		return fmt.Errorf("restore header: %w", err)
	}
	// Reload in-memory state from the restored header.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := binary.Read(f, binary.BigEndian, d.hdr); err != nil {
		return err
	}
	jsonBuf := make([]byte, luks2JSONSize)
	if _, err := f.ReadAt(jsonBuf, luks2BinaryHeaderSize); err != nil {
		return err
	}
	for i, b := range jsonBuf {
		if b == 0 {
			jsonBuf = jsonBuf[:i]
			break
		}
	}
	var newMeta metadata
	if err := json.Unmarshal(jsonBuf, &newMeta); err != nil {
		return err
	}
	*d.meta = newMeta
	return nil
}

// addTokenV2 implements AddToken for LUKS v2.
func (d *deviceV2) addTokenV2(t Token) (int, error) {
	// Find next free token ID.
	id := 0
	for {
		if _, exists := d.meta.Tokens[id]; !exists {
			break
		}
		id++
	}

	// Build token JSON by merging type + keyslots from Token fields with the payload.
	merged := make(map[string]json.RawMessage)
	if len(t.Payload) > 0 {
		if err := json.Unmarshal(t.Payload, &merged); err != nil {
			// Payload is not a JSON object; ignore it.
			merged = make(map[string]json.RawMessage)
		}
	}

	typeJSON, _ := json.Marshal(t.Type)
	merged["type"] = typeJSON

	// Convert int slots to string for JSON (LUKS2 uses string slot IDs in tokens).
	slotStrs := make([]string, len(t.Slots))
	for i, s := range t.Slots {
		slotStrs[i] = strconv.Itoa(s)
	}
	slotsJSON, _ := json.Marshal(slotStrs)
	merged["keyslots"] = slotsJSON

	raw, err := json.Marshal(merged)
	if err != nil {
		return 0, fmt.Errorf("marshal token: %w", err)
	}

	if d.meta.Tokens == nil {
		d.meta.Tokens = make(map[int]json.RawMessage)
	}
	d.meta.Tokens[id] = json.RawMessage(raw)

	if err := d.flushMetadata(); err != nil {
		return 0, err
	}
	return id, nil
}

// removeTokenV2 implements RemoveToken for LUKS v2.
func (d *deviceV2) removeTokenV2(id int) error {
	if _, exists := d.meta.Tokens[id]; !exists {
		return fmt.Errorf("token %d does not exist", id)
	}
	delete(d.meta.Tokens, id)
	return d.flushMetadata()
}
