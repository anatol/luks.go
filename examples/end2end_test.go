package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/anatol/luks.go"
	"github.com/stretchr/testify/assert"
	"github.com/tych0/go-losetup" // fork of github.com/freddierice/go-losetup
	"golang.org/x/sys/unix"
)

// generate several LUKS disks, mount them as loop device and test end-to-end mount process
func runLuksTest(t *testing.T, name string, testPersistentFlags bool, formatArgs ...string) {
	t.Parallel()

	tmpImage, err := ioutil.TempFile("", "luks.go.img."+name)
	assert.NoError(t, err)
	defer tmpImage.Close()
	defer os.Remove(tmpImage.Name())

	assert.NoError(t, tmpImage.Truncate(24*1024*1024))

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
	assert.NoError(t, formatCmd.Run())

	// attach the luks image to a loop device
	loopDev, err := losetup.Attach(tmpImage.Name(), 0, false)
	assert.NoError(t, err)
	defer loopDev.Detach()

	// open the loop device
	openCmd := exec.Command("cryptsetup", "open", loopDev.Path(), name)
	openCmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		openCmd.Stdout = os.Stdout
		openCmd.Stderr = os.Stderr
	}
	assert.NoError(t, openCmd.Run())

	if testPersistentFlags {
		refreshCmd := exec.Command("cryptsetup", "refresh", "--persistent", "--allow-discards", name)
		refreshCmd.Stdin = strings.NewReader(password)
		if testing.Verbose() {
			refreshCmd.Stdout = os.Stdout
			refreshCmd.Stderr = os.Stderr
		}
		assert.NoError(t, refreshCmd.Run())
	}

	expectedUUID := "462c8bc5-f997-4aa5-b97e-6346f5275521"
	// format the crypt device with ext4 filesystem
	formatExt4Cmd := exec.Command("mkfs.ext4", "-q", "-U", expectedUUID, mapperFile)
	if testing.Verbose() {
		formatExt4Cmd.Stdout = os.Stdout
		formatExt4Cmd.Stderr = os.Stderr
	}
	assert.NoError(t, formatExt4Cmd.Run())

	// try to mount it to ext4 filesystem
	tmpMountpoint, err := ioutil.TempDir("", "luks.go.mount."+name)
	assert.NoError(t, err)
	if err := syscall.Mount(mapperFile, tmpMountpoint, "ext4", 0, ""); err != nil {
		assert.Error(t, os.NewSyscallError("mount", err))
	}

	emptyFile := filepath.Join(tmpMountpoint, "empty.txt")
	assert.NoError(t, ioutil.WriteFile(emptyFile, []byte("Hello, world!"), 0666))
	assert.NoError(t, syscall.Unmount(tmpMountpoint, 0))
	assert.NoError(t, os.RemoveAll(tmpMountpoint))

	// close the crypt device
	closeCmd := exec.Command("cryptsetup", "close", name)
	closeCmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		closeCmd.Stdout = os.Stdout
		closeCmd.Stderr = os.Stderr
	}
	assert.NoError(t, closeCmd.Run())

	_, err = os.Stat(mapperFile)
	assert.False(t, err == nil || !os.IsNotExist(err), "It is expected file /dev/mapper/%v does not exist", name)

	dev, err := luks.Open(loopDev.Path())
	assert.NoError(t, err)
	defer dev.Close()

	assert.NoError(t, dev.FlagsAdd(luks.FlagNoReadWorkqueue, luks.FlagSubmitFromCryptCPUs, luks.FlagNoReadWorkqueue /* this is dup */))
	if testPersistentFlags {
		// test adding duplicated flag
		assert.NoError(t, dev.FlagsAdd(luks.FlagAllowDiscards))
	}

	// open the crypt device again, this time with our Golang API
	assert.NoError(t, dev.Unlock(0, []byte(password), name))
	defer luks.Lock(name)

	out, err := exec.Command("cryptsetup", "status", name).CombinedOutput()
	assert.NoError(t, err, "Unable to get status of volume %v", name)

	var expectedFlags string
	if testPersistentFlags {
		expectedFlags = "discards submit_from_crypt_cpus no_read_workqueue"
	} else {
		expectedFlags = "submit_from_crypt_cpus no_read_workqueue"
	}
	assert.Contains(t, string(out), "  flags:   "+expectedFlags+" \n", "expected LUKS flags '%v', got:\n%v", expectedFlags, string(out))

	// dm-crypt mount is an asynchronous process, we need to wait a bit until /dev/mapper/ file appears
	time.Sleep(200 * time.Millisecond)

	// try to mount it to ext4 filesystem
	tmpMountpoint2, err := ioutil.TempDir("", "luks.go.mount."+name)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpMountpoint2)

	if err := syscall.Mount(mapperFile, tmpMountpoint2, "ext4", 0, ""); err != nil {
		assert.Error(t, os.NewSyscallError("mount", err))
	}
	defer syscall.Unmount(tmpMountpoint2, 0)

	data, err := ioutil.ReadFile(filepath.Join(tmpMountpoint2, "empty.txt"))
	assert.NoError(t, err)
	assert.Equal(t, "Hello, world!", string(data))

	if testing.Verbose() {
		stat, err := os.Stat(mapperFile)
		assert.NoError(t, err)
		sys, ok := stat.Sys().(*syscall.Stat_t)
		assert.True(t, ok, "Cannot determine the device major and minor numbers for %s", mapperFile)
		major := unix.Major(sys.Rdev)
		minor := unix.Minor(sys.Rdev)

		udevFile := fmt.Sprintf("/run/udev/data/b%d:%d", major, minor)

		fmt.Printf(">>> %s\n", udevFile)
		content, err := ioutil.ReadFile(udevFile)
		assert.NoError(t, err)
		fmt.Print(string(content))
	}

	out, err = exec.Command("/usr/bin/lsblk", "-rno", "UUID", mapperFile).CombinedOutput()
	assert.NoError(t, err)
	out = bytes.TrimRight(out, "\n")
	assert.Equal(t, expectedUUID, string(out))
}

func TestLUKS1(t *testing.T) {
	runLuksTest(t, "luks1", false, "--type", "luks1", "--iter-time", "5") // lower the unlock time to make tests faster
}

func TestLUKS2(t *testing.T) {
	runLuksTest(t, "luks2", true, "--type", "luks2", "--iter-time", "5")
}
