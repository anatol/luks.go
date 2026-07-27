package luks

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func prepareLuks2Disk(t *testing.T, password string, cryptsetupArgs ...string) *os.File {
	t.Helper()
	disk, err := os.CreateTemp("", "luksv2.go.disk")
	require.NoError(t, err)
	require.NoError(t, disk.Truncate(24*1024*1024))

	args := []string{"luksFormat", "--type", "luks2", "--iter-time", "5", "-q", disk.Name()}
	args = append(args, cryptsetupArgs...)
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	require.NoError(t, cmd.Run())
	return disk
}

func runLuks2Test(t *testing.T, keySlot int, cryptsetupArgs ...string) {
	t.Parallel()

	password := "foobar"
	disk := prepareLuks2Disk(t, password, cryptsetupArgs...)
	defer disk.Close()
	defer os.Remove(disk.Name())

	d, err := initV2Device(disk.Name(), disk, disk)
	require.NoError(t, err)

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)
	require.Equal(t, uuid, d.UUID())

	v, err := d.UnsealVolume(keySlot, []byte(password))
	require.NoError(t, err)
	headerSize := 16777216
	require.Equal(t, uint64(24*1024*1024-headerSize), v.StorageSize)
}

func TestLuks2UnlockBasic(t *testing.T) {
	runLuks2Test(t, 0)
}

func TestLuks2UnlockCustomSectorSize(t *testing.T) {
	runLuks2Test(t, 0, "--sector-size", "2048")
}

func TestLuks2UnlockNonZeroSlotId(t *testing.T) {
	runLuks2Test(t, 4, "--key-slot", "4")
}

func TestLuks2UnlockManyParams(t *testing.T) {
	runLuks2Test(t, 0, "--cipher", "aes-xts-plain64", "--key-size", "512", "--iter-time", "2000", "--pbkdf", "argon2id", "--hash", "sha3-512")
}

func TestLuks2UnlockKeysize256(t *testing.T) {
	runLuks2Test(t, 0, "--cipher", "aes-xts-plain64", "--key-size", "256", "--pbkdf", "argon2id", "--iter-time", "7", "--pbkdf-memory", "1048576", "--hash", "sha256")
}

func TestLuks2Hashes(t *testing.T) {
	// ripemd160 forces use of AF padding
	// It looks like cryptsetup 2.4.0 at Arch Linux defaults to openssl backend that supports blake2b-512 and blake2s-256 only. "blake2b-160", "blake2b-256", "blake2b-384" tests are failing thus disabling it for now.
	hashes := []string{"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "ripemd160", "blake2b-512", "blake2s-256", "whirlpool"}
	for _, h := range hashes {
		t.Run(h, func(t *testing.T) {
			runLuks2Test(t, 0, "--hash", h)
		})
	}
}

func TestLuks2CamelliaBlockCipher(t *testing.T) {
	runLuks2Test(t, 0, "--cipher", "camellia-xts-plain64", "--key-size", "512", "--hash", "sha512", "--iter-time", "800", "--pbkdf", "argon2id", "--pbkdf-memory", "41000")
}

func TestLuks2TwofishBlockCipher(t *testing.T) {
	runLuks2Test(t, 0, "--cipher", "twofish-xts-plain64")
}

func TestLuks2WithIntegrity(t *testing.T) {
	t.Parallel()

	// dm-integrity requires 'root'
	curr, err := user.Current()
	require.NoError(t, err)
	if curr.Username != "root" {
		t.Skip("the test requires root permissions, run it with sudo")
	}

	runLuks2Test(t, 0, "--cipher", "aes-xts-plain64", "--integrity", "hmac-sha256", "--integrity-no-wipe", "--sector-size", "4096")
}

func TestLuks2DetachedHeader(t *testing.T) {
	t.Parallel()

	password := "foobar"

	data, err := os.CreateTemp("", "luksv2.go.data")
	require.NoError(t, err)
	defer os.Remove(data.Name())
	defer data.Close()
	require.NoError(t, data.Truncate(2*1024*1024))

	hdr, err := os.CreateTemp("", "luksv2.go.hdr")
	require.NoError(t, err)
	defer os.Remove(hdr.Name())
	defer hdr.Close()
	require.NoError(t, hdr.Truncate(16*1024*1024))

	cmd := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "--iter-time", "5", "-q", "--header", hdr.Name(), data.Name())
	cmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	require.NoError(t, cmd.Run())

	d, err := OpenWithHeader(data.Name(), hdr.Name())
	require.NoError(t, err)
	defer d.Close()

	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)
}

func TestLuks2UnlockMultipleKeySlots(t *testing.T) {
	t.Parallel()

	password := "barfoo"
	disk := prepareLuks2Disk(t, password)
	defer disk.Close()
	defer os.Remove(disk.Name())

	// now let's add a new keyslot and try to unlock again
	addKeyCmd := exec.Command("cryptsetup", "luksAddKey", "-q", disk.Name())
	password2 := "newpwd"
	addKeyCmd.Stdin = strings.NewReader(password + "\n" + password2)
	if testing.Verbose() {
		addKeyCmd.Stdout = os.Stdout
		addKeyCmd.Stderr = os.Stderr
	}
	require.NoError(t, addKeyCmd.Run())

	d, err := initV2Device(disk.Name(), disk, disk)
	require.NoError(t, err)

	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)

	_, err = d.UnsealVolume(1, []byte(password2))
	require.NoError(t, err)
}

func TestLuks2UnlockWithToken(t *testing.T) {
	t.Parallel()

	password := "foobar"
	disk := prepareLuks2Disk(t, password)
	defer disk.Close()
	defer os.Remove(disk.Name())

	addTokenCmd := exec.Command("cryptsetup", "token", "import", disk.Name())
	slotID := 0
	payload := fmt.Sprintf(`{"type":"clevis","keyslots":["%d"],"jwe":{"ciphertext":"","encrypted_key":"","iv":"","protected":"test\n","tag":""}}`, slotID)
	addTokenCmd.Stdin = strings.NewReader(payload)
	if testing.Verbose() {
		addTokenCmd.Stdout = os.Stdout
		addTokenCmd.Stderr = os.Stderr
	}
	require.NoError(t, addTokenCmd.Run())

	d, err := initV2Device(disk.Name(), disk, disk)
	require.NoError(t, err)

	slots := d.Slots()
	require.Len(t, slots, 1)
	require.Equal(t, 0, slots[0])

	tokens, err := d.Tokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)

	tk := tokens[0]
	require.Equal(t, "clevis", tk.Type)
	require.Equal(t, []int{0}, tk.Slots)

	expected := `{"type":"clevis","keyslots":["0"],"jwe":{"ciphertext":"","encrypted_key":"","iv":"","protected":"test\n","tag":""}}`
	require.Equal(t, expected, string(tk.Payload))

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)
	require.Equal(t, uuid, d.UUID())

	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)
}

func TestLuks2PreferedPriority(t *testing.T) {
	t.Parallel()

	password := "foobar"
	disk := prepareLuks2Disk(t, password)
	defer disk.Close()
	defer os.Remove(disk.Name())

	// now let's increase the priority of the keyslot
	configCmd := exec.Command("cryptsetup", "config", "--priority", "prefer", "--key-slot", "0", disk.Name())
	if testing.Verbose() {
		configCmd.Stdout = os.Stdout
		configCmd.Stderr = os.Stderr
	}
	require.NoError(t, configCmd.Run())

	d, err := initV2Device(disk.Name(), disk, disk)
	require.NoError(t, err)

	uuid, err := blkidUUID(disk.Name())
	require.NoError(t, err)
	require.Equal(t, uuid, d.UUID())

	_, err = d.UnsealVolume(0, []byte(password))
	require.NoError(t, err)

	require.ElementsMatch(t, []int{0}, d.Slots())
}

// TestCheckRequirements verifies that mandatory LUKS2 requirements gate
// unsealing: supported requirements pass, unknown ones produce an error.
func TestCheckRequirements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		requirements []string
		wantErr      string
	}{
		{name: "absent", requirements: nil},
		{name: "opal", requirements: []string{"opal"}},
		// a -vN suffix means incompatible new semantics; must not be pre-approved
		{name: "unknown opal version", requirements: []string{"opal-v2"}, wantErr: `unsupported mandatory requirement "opal-v2"`},
		{name: "unknown", requirements: []string{"online-reencrypt-v2"}, wantErr: `unsupported mandatory requirement "online-reencrypt-v2"`},
		{name: "mixed known and unknown", requirements: []string{"opal", "inline-hw-tags"}, wantErr: `unsupported mandatory requirement "inline-hw-tags"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &deviceV2{meta: &metadata{Config: config{Requirements: tc.requirements}}}
			err := d.checkRequirements()
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

// TestFindStorageSegment verifies segment selection across the activatable
// segment types and the skip-over-linear behavior.
func TestFindStorageSegment(t *testing.T) {
	t.Parallel()

	mkDev := func(segType string) *deviceV2 {
		return &deviceV2{meta: &metadata{
			Segments: map[int]segment{
				0: {Type: "linear"},
				1: {Type: segType},
			},
		}}
	}
	dig := &digest{Segments: []json.Number{"0", "1"}}

	for _, segType := range []string{"crypt", "hw-opal", "hw-opal-crypt"} {
		d := mkDev(segType)
		seg, err := d.findStorageSegment(dig)
		require.NoError(t, err, segType)
		require.Equal(t, segType, seg.Type)
	}

	d := mkDev("linear")
	_, err := d.findStorageSegment(dig)
	require.ErrorContains(t, err, "no storage segment found")
}
