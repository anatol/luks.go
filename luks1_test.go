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
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	defer os.Remove(disk.Name())

	d, err := initV1Device(disk.Name(), disk)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := d.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 {
		t.Fatal("Expected an empty metadata")
	}

	if _, err := d.decryptKeyslot(0, []byte(password)); err != nil {
		t.Fatal(err)
	}

	uuid, err := blkdidUuid(disk.Name())
	if err != nil {
		t.Fatal(err)
	}
	if d.Uuid() != uuid {
		t.Fatalf("wrong UUID: expected %s, got %s", uuid, d.Uuid())
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

	d, err := initV1Device(disk.Name(), disk)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := d.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 {
		t.Fatal("Expected an empty metadata")
	}

	if _, err := d.decryptKeyslot(0, []byte(password)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.decryptKeyslot(1, []byte(password2)); err != nil {
		t.Fatal(err)
	}
}

func TestReadLuksMetaInitialized(t *testing.T) {
	t.Parallel()

	password := "barfoo"
	disk, err := prepareLuks1Disk(t, password)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	defer os.Remove(disk.Name())

	// now let's init luksmeta slots
	initMeta := exec.Command("luksmeta", "init", "-f", "-d", disk.Name())
	if testing.Verbose() {
		initMeta.Stdout = os.Stdout
		initMeta.Stderr = os.Stderr
	}
	if err := initMeta.Run(); err != nil {
		t.Fatal(err)
	}

	uuid1 := "6a6888f3-445d-479b-bc39-1b64e7215464"
	saveMeta1 := exec.Command("luksmeta", "save", "-d", disk.Name(), "-s", "3", "-u", uuid1)
	saveMeta1.Stdin = strings.NewReader("testdata1")
	if testing.Verbose() {
		saveMeta1.Stdout = os.Stdout
		saveMeta1.Stderr = os.Stderr
	}
	if err := saveMeta1.Run(); err != nil {
		t.Fatal(err)
	}

	uuid2 := "f1e1503f-6123-4369-a0fc-58bbe0df93c0"
	saveMeta2 := exec.Command("luksmeta", "save", "-d", disk.Name(), "-s", "6", "-u", uuid2)
	saveMeta2.Stdin = strings.NewReader("testdata2")
	if testing.Verbose() {
		saveMeta2.Stdout = os.Stdout
		saveMeta2.Stderr = os.Stderr
	}
	if err := saveMeta2.Run(); err != nil {
		t.Fatal(err)
	}

	d, err := initV1Device(disk.Name(), disk)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := d.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Fatal("Expected metadata with 2 elements")
	}
	p1 := string(tokens[0].Payload)
	if p1 != "testdata1" {
		t.Fatalf("Wrong metadata for slot %d, expected %s, got %s", 3, "testdata1", p1)
	}
	p2 := string(tokens[1].Payload)
	if p2 != "testdata2" {
		t.Fatalf("Wrong metadata for slot %d, expected %s, got %s", 6, "testdata2", p2)
	}

	uuid, err := blkdidUuid(disk.Name())
	if err != nil {
		t.Fatal(err)
	}
	if d.Uuid() != uuid {
		t.Fatalf("wrong UUID: expected %s, got %s", uuid, d.Uuid())
	}

	// check that we can unlock data for a partition with luks tokens
	if _, err := d.decryptKeyslot(0, []byte(password)); err != nil {
		t.Fatal(err)
	}
}
