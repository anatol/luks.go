package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/anatol/luks.go"
	"github.com/tych0/go-losetup" // fork of github.com/freddierice/go-losetup
)

// generate several LUKS disks, mount them as loop device and test end-to-end mount process
func runLuksTest(t *testing.T, name string, testPersistentFlags bool, formatArgs ...string) {
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

	if testPersistentFlags {
		refreshCmd := exec.Command("cryptsetup", "refresh", "--persistent", "--allow-discards", name)
		refreshCmd.Stdin = strings.NewReader(password)
		if testing.Verbose() {
			refreshCmd.Stdout = os.Stdout
			refreshCmd.Stderr = os.Stderr
		}
		if err := refreshCmd.Run(); err != nil {
			t.Fatalf("Setting persistent flags failed: %v", err)
		}
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

	dev, err := luks.Open(loopDev.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	if err := dev.FlagsAdd(luks.FlagNoReadWorkqueue, luks.FlagSubmitFromCryptCPUs, luks.FlagNoReadWorkqueue /* this is dup */); err != nil {
		t.Fatal(err)
	}
	if testPersistentFlags {
		// test adding duplicated flag
		if err := dev.FlagsAdd(luks.FlagAllowDiscards); err != nil {
			t.Fatal(err)
		}
	}

	// open the crypt device again, this time with our Golang API
	if err := dev.Unlock(0, []byte(password), name); err != nil {
		t.Fatal(err)
	}
	defer luks.Lock(name)

	out, err := exec.Command("cryptsetup", "status", name).CombinedOutput()
	if err != nil {
		t.Fatalf("Unable to get status of volume %v", name)
	}

	var expectedFlags string
	if testPersistentFlags {
		expectedFlags = "discards submit_from_crypt_cpus no_read_workqueue"
	} else {
		expectedFlags = "submit_from_crypt_cpus no_read_workqueue"
	}
	if !bytes.Contains(out, []byte("  flags:   "+expectedFlags+" \n")) {
		t.Fatalf("Expected LUKS flags '%v', got:\n%v", expectedFlags, string(out))
	}

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

func TestLUKS1(t *testing.T) {
	runLuksTest(t, "luks1", false, "--type", "luks1", "--iter-time", "5") // lower the unlock time to make tests faster
}

func TestLUKS2(t *testing.T) {
	runLuksTest(t, "luks2", true, "--type", "luks2", "--iter-time", "5")
}
