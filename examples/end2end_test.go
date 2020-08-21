package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/anatol/luks.go"
	"github.com/tych0/go-losetup" // fork of github.com/freddierice/go-losetup
)

func TestLUKS(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	if u.Username != "root" {
		t.Fatal("Run this test with sudo")
	}

	luksTestCase(t, "LuksV1", "--type", "luks1", "--iter-time", "5") // lower the unlock time to make tests faster
	luksTestCase(t, "LuksV2", "--type", "luks2", "--iter-time", "5")
}

// generate several LUKS disks, mount them as loop device and test end-to-end mount process
func luksTestCase(t *testing.T, name string, formatArgs ...string) {
	f := func(t *testing.T) {
		t.Parallel()

		tmpImage, err := ioutil.TempFile("", "luks.go.img."+name)
		if err != nil {
			t.Fatal(err)
		}
		defer tmpImage.Close()
		defer os.Remove(tmpImage.Name())

		if err := tmpImage.Truncate(24 * 1024 * 1024); err != nil {
			t.Fatal(err)
		}

		mapperFile := "/dev/mapper/" + name
		password := "pwd." + name

		// format a new LUKS device
		args := []string{"luksFormat"}
		args = append(args, formatArgs...)
		args = append(args, "-q", tmpImage.Name())
		formatCmd := exec.Command("cryptsetup", args...)
		formatCmd.Stdin = strings.NewReader(password)
		if testing.Verbose() {
			formatCmd.Stdout = os.Stdout
			formatCmd.Stderr = os.Stderr
		}
		if err := formatCmd.Run(); err != nil {
			t.Fatal(err)
		}

		// attach the luks image to a loop device
		loopDev, err := losetup.Attach(tmpImage.Name(), 0, false)
		if err != nil {
			t.Fatal(err)
		}
		defer loopDev.Detach()

		// open the loop device
		openCmd := exec.Command("cryptsetup", "open", loopDev.Path(), name)
		openCmd.Stdin = strings.NewReader(password)
		if testing.Verbose() {
			openCmd.Stdout = os.Stdout
			openCmd.Stderr = os.Stderr
		}
		if err := openCmd.Run(); err != nil {
			t.Fatal(err)
		}

		// format the crypt device with ext4 filesystem
		formatExt4Cmd := exec.Command("mkfs.ext4", "-q", mapperFile)
		if testing.Verbose() {
			formatExt4Cmd.Stdout = os.Stdout
			formatExt4Cmd.Stderr = os.Stderr
		}
		if err := formatExt4Cmd.Run(); err != nil {
			t.Fatal(err)
		}

		// close the crypt device
		closeCmd := exec.Command("cryptsetup", "close", name)
		closeCmd.Stdin = strings.NewReader(password)
		if testing.Verbose() {
			closeCmd.Stdout = os.Stdout
			closeCmd.Stderr = os.Stderr
		}
		if err := closeCmd.Run(); err != nil {
			t.Fatal(err)
		}

		_, err = os.Stat(mapperFile)
		if err == nil || !os.IsNotExist(err) {
			t.Fatalf("It is expected file /dev/mapper/%v does not exist", name)
		}

		// open the crypt device again, this time with our Golang API
		if err := luks.Open(loopDev.Path(), name, 0, []byte(password)); err != nil {
			t.Fatal(err)
		}
		defer luks.Close(name)

		// dm-crypt mount is an asynchronous process, we need to wait a bit until /dev/mapper/ file appears
		time.Sleep(200 * time.Millisecond)

		// try to mount it to ext4 filesystem
		tmpMountpoint, err := ioutil.TempDir("", "luks.go.mount."+name)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpMountpoint)

		if err := syscall.Mount(mapperFile, tmpMountpoint, "ext4", 0, ""); err != nil {
			t.Fatal(os.NewSyscallError("mount", err))
		}
		defer syscall.Unmount(tmpMountpoint, 0)

		// and then create an empty file to make sure the filesystem still works fine
		emptyFile := filepath.Join(tmpMountpoint, "empty.txt")
		if err := ioutil.WriteFile(emptyFile, []byte("Hello, world!"), 0666); err != nil {
			log.Fatal(err)
		}
	}

	t.Run(name, f)
}
