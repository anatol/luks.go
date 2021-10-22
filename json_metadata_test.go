package luks

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func parseMetadata(t *testing.T, filename string) {
	data, err := ioutil.ReadFile(filename)
	assert.NoError(t, err)

	var meta metadata
	assert.NoError(t, json.Unmarshal(data, &meta))
	assert.Equal(t, uint(4000), meta.Keyslots[0].Af.Stripes)
}

func TestParseMetadata(t *testing.T) {
	parseMetadata(t, "testdata/metadata/1.json")
	parseMetadata(t, "testdata/metadata/2.json")
}
