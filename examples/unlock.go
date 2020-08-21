package main

import (
	"log"

	"github.com/anatol/luks.go"
)

func main() {
	// first setup a loop device with 'sudo losetup -fP ./disk.sample'
	err := luks.Open("/dev/loop0", "foo", 0, []byte("foobar"))
	if err != nil {
		log.Fatal(err)
	}
	// After its done please clean it up with
	//   'sudo cryptsetup close foo'
	//   'sudo losetup -d /dev/loop0'
}
