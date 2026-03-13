package luks

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// jsonNumStr is a numeric value stored as a JSON string (quoted integer).
// LUKS2 stores offsets, sizes, and config values as quoted strings, e.g. "offset": "32768".
// This type ensures round-trip fidelity: reads from either a JSON string or number,
// and always writes as a JSON string.
type jsonNumStr string

func (n jsonNumStr) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(n))
}

func (n *jsonNumStr) UnmarshalJSON(data []byte) error {
	// Accept a JSON string (e.g. "32768") or a bare number (e.g. 32768).
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*n = jsonNumStr(s)
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(data, &num); err != nil {
		return err
	}
	*n = jsonNumStr(num.String())
	return nil
}

func (n jsonNumStr) Int64() (int64, error) {
	return strconv.ParseInt(string(n), 10, 64)
}

type keyslot struct {
	Type     string       `json:"type"`
	KeySize  uint         `json:"key_size"`
	Af       antiForensic `json:"af"`
	Area     area         `json:"area"`
	Kdf      kdf          `json:"kdf"`
	Priority *int         `json:"priority,omitempty"` // need to distinguish 0 (ignore) from absence of the field (normal priority)
}

type antiForensic struct {
	Type    string `json:"type"`
	Stripes uint   `json:"stripes"`
	Hash    string `json:"hash"`
}

type area struct {
	Type       string     `json:"type"`
	Encryption string     `json:"encryption"`
	KeySize    uint       `json:"key_size"`
	Offset     jsonNumStr `json:"offset"`
	Size       jsonNumStr `json:"size"`
}

type kdf struct {
	Type string `json:"type"`
	Salt string `json:"salt"`

	// pbkdf2 specific fields
	Hash       string `json:"hash,omitempty"`
	Iterations uint   `json:"iterations,omitempty"`

	// argon2i/argon2id fields
	Time   uint `json:"time,omitempty"`
	Memory uint `json:"memory,omitempty"`
	Cpus   uint `json:"cpus,omitempty"`
}

type segment struct {
	Type       string     `json:"type"`
	Offset     jsonNumStr `json:"offset"`
	IvTweak    jsonNumStr `json:"iv_tweak"`
	Size       string     `json:"size"` // either 'dynamic' or uint
	Encryption string     `json:"encryption"`
	SectorSize uint       `json:"sector_size"`
	Flags      []string `json:"flags,omitempty"`
}

type digest struct {
	Type       string   `json:"type"`
	Keyslots   []string `json:"keyslots"`
	Segments   []string `json:"segments"`
	Hash       string   `json:"hash"`
	Iterations uint     `json:"iterations"`
	Salt       string   `json:"salt"`
	Digest     string   `json:"digest"`
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
	JSONSize     jsonNumStr `json:"json_size"`
	KeyslotsSize jsonNumStr `json:"keyslots_size"`
	Flags        []string   `json:"flags,omitempty"`
	Requirements configRequirements `json:"requirements,omitempty"`
}

type metadata struct {
	Keyslots map[int]keyslot         `json:"keyslots"`
	Tokens   map[int]json.RawMessage `json:"tokens"`
	Segments map[int]segment         `json:"segments"`
	Digests  map[int]digest          `json:"digests"`
	Config   config                  `json:"config"`
}
