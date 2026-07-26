package luks

import (
	"encoding/json"
	"fmt"
)

type keyslot struct {
	Type    string       `json:"type"`
	KeySize uint         `json:"key_size"`
	Af      antiForensic `json:"af"`
	Area    area         `json:"area"`
	Kdf     kdf          `json:"kdf"`
	// Priority is a pointer to distinguish three states:
	// nil = normal priority (default), 0 = ignore (skip slot), 1 = normal, 2 = high (prefer)
	Priority *int `json:"priority"`
}

type antiForensic struct {
	Type    string `json:"type"`
	Stripes uint   `json:"stripes"`
	Hash    string `json:"hash"`
}

type area struct {
	Type       string      `json:"type"`
	Encryption string      `json:"encryption"`
	KeySize    uint        `json:"key_size"`
	Offset     json.Number `json:"offset"`
	Size       json.Number `json:"size"`
}

type kdf struct {
	Type string `json:"type"`
	Salt string `json:"salt"`

	// pbkdf2 specific fields
	Hash       string `json:"hash"`
	Iterations uint   `json:"iterations"`

	// argon2i fields
	Time   uint `json:"time"`
	Memory uint `json:"memory"`
	Cpus   uint `json:"cpus"`
}

type segment struct {
	Type       string      `json:"type"`
	Offset     json.Number `json:"offset"`
	IvTweak    json.Number `json:"iv_tweak"`
	Size       string      `json:"size"` // "dynamic" (fill remaining space) or a decimal byte count
	Encryption string      `json:"encryption"`
	SectorSize uint        `json:"sector_size"`
	Flags      []string    `json:"flags"`

	// OPAL fields, present only for segment types "hw-opal" and
	// "hw-opal-crypt" (cryptsetup >= 2.7). A pure "hw-opal" segment carries
	// none of the encryption/sector_size/iv_tweak fields above.
	OpalSegmentNumber uint   `json:"opal_segment_number"` // OPAL locking-range index
	OpalKeySize       uint   `json:"opal_key_size"`       // bytes; prefix of the keyslot key
	OpalSegmentSize   string `json:"opal_segment_size"`   // decimal byte count of the locking range
}

type digest struct {
	Type       string        `json:"type"`
	Keyslots   []json.Number `json:"keyslots"`
	Segments   []json.Number `json:"segments"`
	Hash       string        `json:"hash"`
	Iterations uint          `json:"iterations"`
	Salt       string        `json:"salt"`
	Digest     string        `json:"digest"`
}

// configRequirements handles the LUKS2 config requirements field, which may be
// either a JSON array of strings (["opal"]) as per spec, or a JSON object
// ({"mandatory": ["opal"]}) as emitted by cryptsetup in practice.
type configRequirements []string

func (r *configRequirements) UnmarshalJSON(data []byte) error {
	// Try the spec-compliant array form: ["opal", ...]
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*r = arr
		return nil
	}
	// Try the cryptsetup object form: {"mandatory": ["opal", ...]}
	var obj struct {
		Mandatory []string `json:"mandatory"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("config.requirements: cannot parse as array or object: %w", err)
	}
	*r = obj.Mandatory
	return nil
}

type config struct {
	JSONSize     json.Number        `json:"json_size"`
	KeyslotsSize json.Number        `json:"keyslots_size"`
	Flags        []string           `json:"flags"`
	Requirements configRequirements `json:"requirements"`
}

type metadata struct {
	Keyslots map[int]keyslot         `json:"keyslots"`
	Tokens   map[int]json.RawMessage `json:"tokens"`
	Segments map[int]segment         `json:"segments"`
	Digests  map[int]digest          `json:"digests"`
	Config   config                  `json:"config"`
}
