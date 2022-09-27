package luks

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func prepareLuks1Disk(t *testing.T, password string, cryptsetupArgs ...string) (*os.File, error) {
	disk, err := os.CreateTemp("", "luksv1.go.disk")
	require.NoError(t, err)
	require.NoError(t, disk.Truncate(2*1024*1024))

	args := []string{"luksFormat", "--type", "luks1", "--iter-time", "5", "-q", disk.Name()}
	args = append(args, cryptsetupArgs...)
	cmd := exec.Command("cryptsetup", args...)

	cmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	require.NoError(t, cmd.Run())
	return disk, err
}

func runLuks1Test(t *testing.T, cryptsetupArgs ...string) {
	t.Parallel()

	password := "foobar"
	disk, err := prepareLuks1Disk(t, password, cryptsetupArgs...)
	require.NoError(t, err)
	defer disk.Close()
	defer os.Remove(disk.Name())

	d, err := initV1Device(disk.Name(), disk)
	require.NoError(t, err)

	tokens, err := d.Tokens()
	require.NoError(t, err)
	require.Empty(t, tokens)

	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)
	require.Equal(t, uuid, d.UUID())
}

func TestLuks1Unlock(t *testing.T) {
	runLuks1Test(t)
}

func TestLuks1Sha256(t *testing.T) {
	runLuks1Test(t, "--hash", "sha256")
}

func TestLuks1Sha512(t *testing.T) {
	runLuks1Test(t, "--hash", "sha512")
}

func TestLuks1UnlockMultipleKeySlots(t *testing.T) {
	t.Parallel()

	password := "barfoo"
	disk, err := prepareLuks1Disk(t, password)
	require.NoError(t, err)
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
	require.NoError(t, addKeyCmd.Run())

	d, err := initV1Device(disk.Name(), disk)
	require.NoError(t, err)

	tokens, err := d.Tokens()
	require.NoError(t, err)
	require.Empty(t, tokens)

	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)

	_, err = d.UnsealVolume(1, []byte(password2))
	require.NoError(t, err)
}

func TestReadLuksMetaInitialized(t *testing.T) {
	t.Parallel()

	password := "barfoo"
	disk, err := prepareLuks1Disk(t, password)
	require.NoError(t, err)
	defer disk.Close()
	defer os.Remove(disk.Name())

	// now let's init luksmeta slots
	initMeta := exec.Command("luksmeta", "init", "-f", "-d", disk.Name())
	if testing.Verbose() {
		initMeta.Stdout = os.Stdout
		initMeta.Stderr = os.Stderr
	}
	require.NoError(t, initMeta.Run())

	uuid1 := "6a6888f3-445d-479b-bc39-1b64e7215464"
	saveMeta1 := exec.Command("luksmeta", "save", "-d", disk.Name(), "-s", "3", "-u", uuid1)
	saveMeta1.Stdin = strings.NewReader("testdata1")
	if testing.Verbose() {
		saveMeta1.Stdout = os.Stdout
		saveMeta1.Stderr = os.Stderr
	}
	require.NoError(t, saveMeta1.Run())

	uuid2 := "f1e1503f-6123-4369-a0fc-58bbe0df93c0"
	saveMeta2 := exec.Command("luksmeta", "save", "-d", disk.Name(), "-s", "6", "-u", uuid2)
	saveMeta2.Stdin = strings.NewReader("testdata2")
	if testing.Verbose() {
		saveMeta2.Stdout = os.Stdout
		saveMeta2.Stderr = os.Stderr
	}
	require.NoError(t, saveMeta2.Run())

	d, err := initV1Device(disk.Name(), disk)
	require.NoError(t, err)

	tokens, err := d.Tokens()
	require.NoError(t, err)
	require.Len(t, tokens, 2)
	t1 := tokens[0]
	require.Equal(t, 3, t1.ID)
	require.Equal(t, "testdata1", string(t1.Payload), "Wrong metadata for token %d", t1.ID)
	t2 := tokens[1]
	require.Equal(t, 6, t2.ID)
	require.Equal(t, "testdata2", string(t2.Payload), "Wrong metadata for token %d", t2.ID)

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)
	require.Equal(t, uuid, d.UUID())

	// check that we can unlock data for a partition with luks tokens
	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)
}
