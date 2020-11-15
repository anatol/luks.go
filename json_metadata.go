package luks

import "encoding/json"

type keyslot struct {
	Type     string       `json:"type"`
	KeySize  uint         `json:"key_size"`
	Af       antiForensic `json:"af"`
	Area     area         `json:"area"`
	Kdf      kdf          `json:"kdf"`
	Priority string       `json:"priority"` // it is actually a number, but we need to distinguish '0' (ignore), from absence of the field (normal priority)
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
	Size       string      `json:"size"` // either 'dynamic' or uint
	Encryption string      `json:"encryption"`
	SectorSize uint        `json:"sector_size"`
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

type config struct {
	JsonSize     json.Number `json:"json_size"`
	KeyslotsSize json.Number `json:"keyslots_size"`
	Flags        []string    `json:"flags"`
	Requirements []string    `json:"requirements"`
}

type metadata struct {
	Keyslots map[int]keyslot         `json:"keyslots"`
	Tokens   map[int]json.RawMessage `json:"tokens"`
	Segments map[int]segment         `json:"segments"`
	Digests  map[int]digest          `json:"digests"`
	Config   config                  `json:"config"`
}
