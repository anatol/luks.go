package luks

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
)

func xorSlices(src1, src2 []byte, dest []byte) {
	// src1, src2, dest are all the same size
	for i := range dest {
		dest[i] = src1[i] ^ src2[i]
	}
}

func hashBuffer(src []byte, h hash.Hash, iv int, result []byte) []byte {
	ivSlice := make([]byte, 4)
	binary.BigEndian.PutUint32(ivSlice, uint32(iv))

	h.Reset()
	h.Write(ivSlice)
	h.Write(src)
	return h.Sum(result)
}

func diffuse(src []byte, h hash.Hash) []byte {
	// src and dest are of the same size
	sliceSize := len(src)
	result := make([]byte, 0, sliceSize)
	digestSize := h.Size()

	for i := 0; i < sliceSize/digestSize; i++ {
		result = hashBuffer(src[i*digestSize:(i+1)*digestSize], h, i, result)
	}

	if padding := sliceSize % digestSize; padding != 0 {
		result = hashBuffer(src[sliceSize-padding:], h, sliceSize/digestSize, result)
		result = result[:sliceSize]
	}

	return result
}

func afSplit(src []byte, blockNum int, h hash.Hash) ([]byte, error) {
	blockSize := len(src)
	buffer := make([]byte, blockSize)
	dest := make([]byte, blockSize*blockNum)

	// first blockNum-1 are random data
	// the very last block value depends on input src data
	randomDataSize := (blockNum - 1) * blockSize
	n, err := rand.Read(dest[:randomDataSize])
	if err != nil {
		return nil, err
	}
	if n != randomDataSize {
		return nil, fmt.Errorf("Expected to generate %v bytes of random data, got %v", randomDataSize, n)
	}

	for i := 0; i < blockNum-1; i++ {
		b := dest[blockSize*i : blockSize*(i+1)]

		xorSlices(b, buffer, buffer)
		buffer = diffuse(buffer, h)
	}

	xorSlices(src, buffer, dest[randomDataSize:randomDataSize+blockSize])

	return dest, nil
}

func afMerge(src []byte, blockSize, blockNum int, h hash.Hash) ([]byte, error) {
	buffer := make([]byte, blockSize)

	if blockSize*blockNum > len(src) {
		return nil, fmt.Errorf("af merge input buffer size mismatch %v * %v != %v", blockSize, blockNum, len(src))
	}

	for i := 0; i < blockNum-1; i++ {
		b := src[blockSize*i : blockSize*(i+1)]

		xorSlices(b, buffer, buffer)
		buffer = diffuse(buffer, h)
	}

	xorSlices(src[blockSize*(blockNum-1):blockSize*blockNum], buffer, buffer)

	return buffer, nil
}
