package luks

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func prepareLuks1Disk(t *testing.T, password string) (*os.File, error) {
	disk, err := ioutil.TempFile("", "luksv1.go.disk")
	if err != nil {
		t.Fatal(err)
	}

	if err := disk.Truncate(2 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("cryptsetup", "luksFormat", "--type", "luks1", "--iter-time", "5", "-q", disk.Name())

	cmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return disk, err
}

func TestLuks1Unlock(t *testing.T) {
	t.Parallel()

	password := "foobar"
	disk, err := prepareLuks1Disk(t, password)
	defer disk.Close()
	defer os.Remove(disk.Name())

	luks, err := luks1OpenDevice(disk)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := luks.unlockKeyslot(disk, 0, []byte(password)); err != nil {
		t.Fatal(err)
	}
}

func TestLuks1UnlockMultipleKeySlots(t *testing.T) {
	t.Parallel()

	password := "barfoo"
	disk, err := prepareLuks1Disk(t, password)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	defer os.Remove(disk.Name())

	// now let's add a new keyslot and try to unlock again
	addKeyCmd := exec.Command("cryptsetup", "luksAddKey", "-q", disk.Name())
	password2 := "newpwd111"
	addKeyCmd.Stdin = strings.NewReader(password + "\n" + password2)
	if testing.Verbose() {
		addKeyCmd.Stdout = os.Stdout
		addKeyCmd.Stderr = os.Stderr
	}
	if err := addKeyCmd.Run(); err != nil {
		t.Fatal(err)
	}

	luks, err := luks1OpenDevice(disk)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := luks.unlockAnyKeyslot(disk, []byte(password)); err != nil {
		t.Fatal(err)
	}
	if _, err := luks.unlockAnyKeyslot(disk, []byte(password2)); err != nil {
		t.Fatal(err)
	}
}
