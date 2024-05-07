package luks

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func prepareLuksDisk(t *testing.T, password string, typ string, extraArgs ...string) (*os.File, error) {
	disk, err := os.CreateTemp("", typ+".go.disk")
	require.NoError(t, err)
	require.NoError(t, disk.Truncate(2*1024*1024))

	args := []string{"luksFormat", "--type", typ, "-q", disk.Name()}
	args = append(args, extraArgs...)
	cmd := exec.Command("cryptsetup", args...)

	cmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	require.NoError(t, cmd.Run())
	return disk, err
}

func TestConvertV1toV2(t *testing.T) {
	t.Parallel()

	password := "test1"

	disk, err := prepareLuksDisk(t, password, "luks1")
	require.NoError(t, err)
	defer disk.Close()
	defer os.Remove(disk.Name())

	d, err := initV1Device(disk.Name(), disk)
	require.NoError(t, err)

	tokens, err := d.Tokens()
	require.NoError(t, err)
	require.Empty(t, tokens)

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)
	require.Equal(t, uuid, d.UUID())

	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)

	// convert it to V2
	err = exec.Command("cryptsetup", "convert", "--type", "luks2", disk.Name()).Run()
	require.NoError(t, err)

	d2, err := initV2Device(disk.Name(), disk)
	require.NoError(t, err)
	_, err = d2.UnsealVolume(0, []byte(password))
	require.NoError(t, err)

	// convert back to V1
	err = exec.Command("cryptsetup", "convert", "--type", "luks1", disk.Name()).Run()
	require.NoError(t, err)

	d3, err := initV1Device(disk.Name(), disk)
	require.NoError(t, err)
	_, err = d3.UnsealVolume(0, []byte(password))
	require.NoError(t, err)
}

func TestConvertV2toV1(t *testing.T) {
	t.Parallel()

	password := "test2"

	disk, err := prepareLuksDisk(t, password, "luks2", "--sector-size", "512", "--pbkdf", "pbkdf2")
	require.NoError(t, err)
	defer disk.Close()
	defer os.Remove(disk.Name())

	d, err := initV2Device(disk.Name(), disk)
	require.NoError(t, err)

	tokens, err := d.Tokens()
	require.NoError(t, err)
	require.Empty(t, tokens)

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)
	require.Equal(t, uuid, d.UUID())

	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)

	// convert it to V1
	cmd := exec.Command("cryptsetup", "convert", "--type", "luks1", disk.Name())
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	require.NoError(t, err)

	d2, err := initV1Device(disk.Name(), disk)
	require.NoError(t, err)
	_, err = d2.UnsealVolume(0, []byte(password))
	require.NoError(t, err)

	// convert back to V2
	err = exec.Command("cryptsetup", "convert", "--type", "luks2", disk.Name()).Run()
	require.NoError(t, err)

	d3, err := initV2Device(disk.Name(), disk)
	require.NoError(t, err)
	_, err = d3.UnsealVolume(0, []byte(password))
	require.NoError(t, err)
}
