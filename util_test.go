package luks

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsPowerOf2(t *testing.T) {
	valid := []uint{1, 2, 4, 1 << 3, 1 << 8, 1 << 24}
	invalid := []uint{3, 5, 9, 323, 34322, 6521212322}

	for _, v := range valid {
		require.True(t, isPowerOfTwo(v))
	}

	for _, v := range invalid {
		require.False(t, isPowerOfTwo(v))
	}
}

func TestRundup(t *testing.T) {
	require.Equal(t, 0, roundUp(0, 8))
	require.Equal(t, 8, roundUp(1, 8))
}

func TestFromNulEndedSlice(t *testing.T) {
	check := func(input []byte, expected string) {
		str := fixedArrayToString(input)
		require.Equal(t, expected, str)
	}

	check([]byte{}, "")
	check([]byte{'r'}, "r")
	check([]byte{'h', 'e', 'l', 'l', 'o', ',', ' '}, "hello, ")
	check([]byte{'h', '\x00', 'l', 'l', 'o', ',', ' '}, "h")
	check([]byte{'\x00'}, "")
}

func blkidUUID(filename string) (string, error) {
	cmdOut, err := exec.Command("blkid", "-s", "UUID", "-o", "value", filename).CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.Trim(string(cmdOut), "\n"), nil
}
