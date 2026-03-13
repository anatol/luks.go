package luks

// luks1_write.go implements write operations for LUKS v1 devices.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// luksV1SlotDisabled is the Active field value for an inactive LUKS v1 keyslot.
const luksV1SlotDisabled = 0x0000DEAD

// luksV1KeyslotSectors returns the number of 512-byte sectors needed for one
// keyslot's AF-split key material.
func luksV1KeyslotSectors(keyBytes uint32) int {
	rawSize := int(keyBytes) * stripesNum
	return (rawSize + storageSectorSize - 1) / storageSectorSize
}

// luksV1KeyslotOffset returns the sector offset for keyslot slotIdx.
// Slots are laid out consecutively starting at sector 8 (byte 4096).
func luksV1KeyslotOffset(slotIdx int, keyBytes uint32) uint32 {
	return uint32(8 + slotIdx*luksV1KeyslotSectors(keyBytes))
}

// luksV1PayloadOffset calculates the PayloadOffset (in sectors) for a LUKS v1
// header with the given key size.  It rounds up to the nearest 1 MiB boundary
// (2048 sectors) after all 8 keyslots.
func luksV1PayloadOffset(keyBytes uint32) uint32 {
	allEnd := 8 + 8*luksV1KeyslotSectors(keyBytes)
	return uint32(roundUp(allEnd, 2048))
}

// openHdrRW opens the header file for this device in read-write mode.
func (d *deviceV1) openHdrRW() (*os.File, error) {
	return os.OpenFile(d.hdrF.Name(), os.O_RDWR, 0)
}

// writeHeaderV1 serialises hdr in big-endian and writes it at offset 0 of f.
func writeHeaderV1(f *os.File, hdr *headerV1) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return binary.Write(f, binary.BigEndian, hdr)
}

// encryptKeyMaterialV1 AF-splits masterKey, encrypts with afKey, and writes the
// result to the keyslot's on-disk area.
func encryptKeyMaterialV1(f *os.File, hdr *headerV1, slotIdx int, masterKey, passphrase []byte, h func() hash.Hash) error {
	slot := &hdr.KeySlots[slotIdx]

	// Derive AF key.
	afKey := pbkdf2.Key(passphrase, slot.Salt[:], int(slot.Iterations), int(hdr.KeyBytes), h)
	defer clearSlice(afKey)

	// AF-split the master key.
	splitKey, err := afSplit(masterKey, stripesNum, h())
	if err != nil {
		return fmt.Errorf("afSplit: %w", err)
	}
	defer clearSlice(splitKey)

	// Encrypt the split key with XTS.
	cipherName := fixedArrayToString(hdr.CipherName[:])
	cf, err := getCipher(cipherName)
	if err != nil {
		return err
	}
	ciph, err := xts.NewCipher(cf, afKey)
	if err != nil {
		return fmt.Errorf("xts.NewCipher: %w", err)
	}
	keyslotSize := int(hdr.KeyBytes) * stripesNum
	for i := 0; i < keyslotSize/storageSectorSize; i++ {
		block := splitKey[i*storageSectorSize : (i+1)*storageSectorSize]
		ciph.Encrypt(block, block, uint64(i))
	}

	offset := int64(slot.KeyMaterialOffset) * storageSectorSize
	if _, err := f.WriteAt(splitKey, offset); err != nil {
		return fmt.Errorf("write keyslot material: %w", err)
	}
	return nil
}

// addKeyToSlot implements AddKey / AddKeyToSlot for LUKS v1.
// slotIdx == -1 means auto-select the first free slot.
func (d *deviceV1) addKeyToSlot(slotIdx int, existingPassphrase, newPassphrase []byte) (int, error) {
	// Recover master key using any existing passphrase.
	masterKey, _, err := d.recoverMasterKeyV1(existingPassphrase)
	if err != nil {
		return 0, err
	}
	defer clearSlice(masterKey)

	// Resolve target slot.
	if slotIdx == -1 {
		slotIdx = -1
		for i, ks := range d.hdr.KeySlots {
			if ks.Active != luksV1SlotEnabled {
				slotIdx = i
				break
			}
		}
		if slotIdx == -1 {
			return 0, fmt.Errorf("no free keyslot available")
		}
	} else {
		if slotIdx < 0 || slotIdx >= len(d.hdr.KeySlots) {
			return 0, fmt.Errorf("keyslot %d out of range", slotIdx)
		}
		if d.hdr.KeySlots[slotIdx].Active == luksV1SlotEnabled {
			return 0, fmt.Errorf("keyslot %d is already in use", slotIdx)
		}
	}

	algo := fixedArrayToString(d.hdr.HashSpec[:])
	h, _ := getHashAlgo(algo)
	if h == nil {
		return 0, fmt.Errorf("unknown hash spec: %s", algo)
	}

	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return 0, err
	}

	// Use a fixed iteration count. Real time-based calibration can be added later.
	const defaultIter = 100_000

	d.hdr.KeySlots[slotIdx] = keySlot{
		Active:            luksV1SlotEnabled,
		Iterations:        defaultIter,
		Salt:              salt,
		KeyMaterialOffset: luksV1KeyslotOffset(slotIdx, d.hdr.KeyBytes),
		Stripes:           stripesNum,
	}

	f, err := d.openHdrRW()
	if err != nil {
		return 0, err
	}
	defer f.Close()

	if err := encryptKeyMaterialV1(f, d.hdr, slotIdx, masterKey, newPassphrase, h); err != nil {
		return 0, err
	}
	if err := writeHeaderV1(f, d.hdr); err != nil {
		return 0, err
	}
	return slotIdx, nil
}

// recoverMasterKeyV1 tries all active keyslots with passphrase, returns master key + slot.
func (d *deviceV1) recoverMasterKeyV1(passphrase []byte) (masterKey []byte, slotIdx int, err error) {
	for _, i := range d.Slots() {
		v, e := d.UnsealVolume(i, passphrase)
		if e == nil {
			key := v.key
			v.key = nil
			return key, i, nil
		}
	}
	return nil, -1, ErrPassphraseDoesNotMatch
}

// killSlotV1Core wipes keyslot material and marks the slot disabled.
// Callers must verify safety (≥1 other slot, passphrase checks) before calling this.
func (d *deviceV1) killSlotV1Core(f *os.File, slotIdx int) error {
	slot := d.hdr.KeySlots[slotIdx]
	keyslotSize := int(d.hdr.KeyBytes) * stripesNum

	// Overwrite with random bytes.
	random := make([]byte, keyslotSize)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	offset := int64(slot.KeyMaterialOffset) * storageSectorSize
	if _, err := f.WriteAt(random, offset); err != nil {
		return fmt.Errorf("wipe keyslot material: %w", err)
	}

	// Disable the slot and persist the header.
	d.hdr.KeySlots[slotIdx].Active = luksV1SlotDisabled
	return writeHeaderV1(f, d.hdr)
}

// killSlotV1 implements KillSlot for LUKS v1.
// passphrase must match a *different* active keyslot.
func (d *deviceV1) killSlotV1(slotIdx int, passphrase []byte) error {
	if slotIdx < 0 || slotIdx >= len(d.hdr.KeySlots) {
		return fmt.Errorf("keyslot %d out of range", slotIdx)
	}
	if d.hdr.KeySlots[slotIdx].Active != luksV1SlotEnabled {
		return fmt.Errorf("keyslot %d is not active", slotIdx)
	}
	// Verify passphrase matches a different slot.
	found := false
	for i, ks := range d.hdr.KeySlots {
		if i == slotIdx || ks.Active != luksV1SlotEnabled {
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
	return d.killSlotV1Core(f, slotIdx)
}

// removeKeyV1 implements RemoveKey for LUKS v1.
func (d *deviceV1) removeKeyV1(passphrase []byte) error {
	_, matchedSlot, err := d.recoverMasterKeyV1(passphrase)
	if err != nil {
		return err
	}
	// Ensure at least one other active slot remains.
	otherActive := false
	for i, ks := range d.hdr.KeySlots {
		if i != matchedSlot && ks.Active == luksV1SlotEnabled {
			otherActive = true
			break
		}
	}
	if !otherActive {
		return fmt.Errorf("refusing to remove the last active keyslot")
	}

	f, err := d.openHdrRW()
	if err != nil {
		return err
	}
	defer f.Close()
	return d.killSlotV1Core(f, matchedSlot)
}

// changeKeyV1 implements ChangeKey for LUKS v1.
func (d *deviceV1) changeKeyV1(existingPassphrase, newPassphrase []byte) error {
	_, matchedSlot, err := d.recoverMasterKeyV1(existingPassphrase)
	if err != nil {
		return err
	}

	if len(d.Slots()) > 1 {
		// Safe swap: add new key first, then kill old slot.
		_, err := d.addKeyToSlot(-1, existingPassphrase, newPassphrase)
		if err != nil {
			return fmt.Errorf("add new key: %w", err)
		}
		return d.killSlotV1(matchedSlot, newPassphrase)
	}

	// Single slot: overwrite in place.
	masterKey, _, err := d.recoverMasterKeyV1(existingPassphrase)
	if err != nil {
		return err
	}
	defer clearSlice(masterKey)

	algo := fixedArrayToString(d.hdr.HashSpec[:])
	h, _ := getHashAlgo(algo)
	if h == nil {
		return fmt.Errorf("unknown hash spec: %s", algo)
	}

	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	d.hdr.KeySlots[matchedSlot].Salt = salt

	f, err := d.openHdrRW()
	if err != nil {
		return err
	}
	defer f.Close()

	if err := encryptKeyMaterialV1(f, d.hdr, matchedSlot, masterKey, newPassphrase, h); err != nil {
		return err
	}
	return writeHeaderV1(f, d.hdr)
}

// headerBackupV1 implements HeaderBackup for LUKS v1.
func (d *deviceV1) headerBackupV1(path string) error {
	backupSize := int64(d.hdr.PayloadOffset) * storageSectorSize
	buf := make([]byte, backupSize)
	if _, err := d.hdrF.ReadAt(buf, 0); err != nil {
		return fmt.Errorf("read header region: %w", err)
	}
	return os.WriteFile(path, buf, 0600)
}

// headerRestoreV1 implements HeaderRestore for LUKS v1.
func (d *deviceV1) headerRestoreV1(path string) error {
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
	// Reload in-memory header.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return binary.Read(f, binary.BigEndian, d.hdr)
}
