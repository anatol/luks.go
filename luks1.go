package luks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
	"hash"
	"os"
)

// LUKS v1 format is specified here
// https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf
type headerV1 struct {
	Magic         [6]byte
	Version       uint16
	CipherName    [32]byte
	CipherMode    [32]byte
	HashSpec      [32]byte
	PayloadOffset uint32
	KeyBytes      uint32
	MkDigest      [20]byte
	MkDigestSalt  [32]byte
	MkDigestIter  uint32
	UUID          [40]byte
	KeySlots      [8]keySlot
}

type keySlot struct {
	Active            uint32
	Iterations        uint32
	Salt              [32]byte
	KeyMaterialOffset uint32 // offset in sectors
	Stripes           uint32
}

type luks1Device struct {
	hdr *headerV1
}

func luks1OpenDevice(f *os.File) (*luks1Device, error) {
	var hdr headerV1

	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	if err := binary.Read(f, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	return &luks1Device{hdr: &hdr}, nil
}

func (d *luks1Device) uuid() string {
	return fixedArrayToString(d.hdr.UUID[:])
}

func (d *luks1Device) unlockKeyslot(f *os.File, keyslotIdx int, passphrase []byte) (*volumeInfo, error) {
	header := d.hdr

	keyslots := header.KeySlots
	if keyslotIdx < 0 || keyslotIdx >= len(keyslots) {
		return nil, fmt.Errorf("keyslot %d is out of range of available slots", keyslotIdx)
	}
	slot := keyslots[keyslotIdx]

	h, err := luks1Hash(fixedArrayToString(header.HashSpec[:]))
	if err != nil {
		return nil, err
	}

	afKey := deriveLuks1AfKey(passphrase, slot, int(header.KeyBytes), h)
	defer clearSlice(afKey)

	finalKey, err := decryptLuks1VolumeKey(f, keyslotIdx, header, slot, afKey, h)
	if err != nil {
		return nil, err
	}

	// verify with digest
	generatedDigest := pbkdf2.Key(finalKey, header.MkDigestSalt[:], int(header.MkDigestIter), int(header.KeyBytes), h)
	defer clearSlice(generatedDigest)
	if !bytes.Equal(generatedDigest[:20], header.MkDigest[:]) {
		return nil, ErrPassphraseDoesNotMatch
	}

	encryption := fixedArrayToString(header.CipherName[:]) + "-" + fixedArrayToString(header.CipherMode[:])
	info := &volumeInfo{
		key:               finalKey,
		digestId:          0,
		luksType:          "LUKS1",
		storageSize:       0, // dynamic size
		storageOffset:     uint64(header.PayloadOffset),
		storageEncryption: encryption,
		storageIvTweak:    0,
		storageSectorSize: storageSectorSize,
	}

	return info, nil
}

func (d *luks1Device) unlockAnyKeyslot(f *os.File, passphrase []byte) (*volumeInfo, error) {
	for k, s := range d.hdr.KeySlots {
		const luksKeyEnabled = 0xAC71F3
		if s.Active != luksKeyEnabled {
			continue
		}

		volumeKey, err := d.unlockKeyslot(f, k, passphrase)
		if err == nil {
			return volumeKey, nil
		} else if err == ErrPassphraseDoesNotMatch {
			continue
		} else {
			return nil, err
		}
	}
	return nil, ErrPassphraseDoesNotMatch
}

func decryptLuks1VolumeKey(f *os.File, keyslotIdx int, hdr *headerV1, slot keySlot, afKey []byte, h func() hash.Hash) ([]byte, error) {
	// decrypt keyslotIdx area using the derived key
	keyslotSize := hdr.KeyBytes * stripesNum
	if keyslotSize%storageSectorSize != 0 {
		return nil, fmt.Errorf("keyslot[%v] size %v is not multiple of the sector size %v", keyslotIdx, keyslotSize, storageSectorSize)
	}
	keyData := make([]byte, keyslotSize)
	defer clearSlice(keyData)

	if _, err := f.ReadAt(keyData, int64(slot.KeyMaterialOffset)*storageSectorSize); err != nil {
		return nil, err
	}

	ciph, err := buildLuks1AfCipher(hdr, afKey)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(keyslotSize/storageSectorSize); i++ {
		block := keyData[i*storageSectorSize : (i+1)*storageSectorSize]
		ciph.Decrypt(block, block, uint64(i))
	}

	// anti-forensic merge
	if slot.Stripes != stripesNum {
		return nil, fmt.Errorf("LUKS currently supports only af with 4000 stripes")
	}
	return afMerge(keyData, int(hdr.KeyBytes), int(slot.Stripes), h())
}

func buildLuks1AfCipher(hdr *headerV1, afKey []byte) (*xts.Cipher, error) {
	var cipherFunc func(key []byte) (cipher.Block, error)

	cipherName := fixedArrayToString(hdr.CipherName[:])
	switch cipherName {
	case "aes":
		cipherFunc = aes.NewCipher
	default:
		return nil, fmt.Errorf("Unknown cipher: %v", cipherName)
	}

	cipherMode := fixedArrayToString(hdr.CipherMode[:])
	switch cipherMode {
	case "xts-plain64":
		return xts.NewCipher(cipherFunc, afKey)
	default:
		return nil, fmt.Errorf("Unknown encryption mode: %v", cipherMode)
	}
}

func deriveLuks1AfKey(passphrase []byte, slot keySlot, keySize int, h func() hash.Hash) []byte {
	return pbkdf2.Key(passphrase, slot.Salt[:], int(slot.Iterations), keySize, h)
}

func luks1Hash(hashSpecName string) (func() hash.Hash, error) {
	switch hashSpecName {
	case "sha256":
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("Unknown hash spec algorithm: %v", hashSpecName)
	}
}
