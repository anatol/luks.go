package luks

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func parseMetadata(t *testing.T, filename string) {
	data, err := os.ReadFile(filename)
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.Equal(t, uint(4000), meta.Keyslots[0].Af.Stripes)
}

func TestParseMetadata(t *testing.T) {
	parseMetadata(t, "testdata/metadata/1.json")
	parseMetadata(t, "testdata/metadata/2.json")
}
