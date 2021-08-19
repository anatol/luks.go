package luks

import (
	"os/exec"
	"strings"
	"testing"
)

func TestIsPowerOf2(t *testing.T) {
	valid := []uint{1, 2, 4, 1 << 3, 1 << 8, 1 << 24}
	invalid := []uint{3, 5, 9, 323, 34322, 6521212322}

	for _, v := range valid {
		if !isPowerOfTwo(v) {
			t.Fatalf("Number %v is reported as not power of 2", v)
		}
	}

	for _, v := range invalid {
		if isPowerOfTwo(v) {
			t.Fatalf("Number %v is reported as power of 2", v)
		}
	}
}

func TestRundup(t *testing.T) {
	compare := func(expected, got int) {
		if expected != got {
			t.Fatalf("expected %v, got %v", expected, got)
		}
	}

	compare(0, roundUp(0, 8))
	compare(8, roundUp(1, 8))
}

func TestFromNulEndedSlice(t *testing.T) {
	check := func(input []byte, expected string) {
		str := fixedArrayToString(input)
		if str != expected {
			t.Fatalf("Expected string %v, got %v", expected, str)
		}
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
