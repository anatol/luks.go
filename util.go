package luks

import (
	"bytes"
)

func isPowerOfTwo(x uint) bool {
	return (x & (x - 1)) == 0
}

func roundUp(n int, divider int) int {
	return (n + divider - 1) / divider * divider
}

func fixedArrayToString(buff []byte) string {
	idx := bytes.IndexByte(buff, 0)
	if idx != -1 {
		buff = buff[:idx]
	}
	return string(buff)
}

func clearSlice(slice []byte) {
	for i, _ := range slice {
		slice[i] = 0
	}
}
