package main

import (
	"log"

	"github.com/anatol/luks.go"
)

// before running this example please setup a loop device with 'sudo losetup -fP ./disk.sample'
func main() {
	dev, err := luks.Open("/dev/loop0")
	if err != nil {
		log.Fatal(err)
	}
	err = dev.Unlock(0, []byte("foobar"), "foo")
	if err != nil {
		log.Fatal(err)
	}
	// After its done please clean it up with
	//   'sudo cryptsetup close foo'
	//   'sudo losetup -d /dev/loop0'
}
