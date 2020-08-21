package luks

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func parseMetadata(t *testing.T, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	var meta metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}

	if meta.Keyslots[0].Af.Stripes != 4000 {
		t.Fatalf("keyslots[0].af.stripes expected to be %v was %v",
			4000, meta.Keyslots[0].Af.Stripes)
	}
}

func TestParseMetadata(t *testing.T) {
	parseMetadata(t, "testdata/metadata/1.json")
	parseMetadata(t, "testdata/metadata/2.json")
}
