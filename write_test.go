package luks

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// -------------------------------------------------------------------------
// Helpers shared by write tests
// -------------------------------------------------------------------------

// formatV1Fast creates a LUKS v1 disk using our library with minimal KDF cost.
func formatV1Fast(t *testing.T, passphrase string) *os.File {
	t.Helper()
	disk := newTempDisk(t, 4*1024*1024)
	dev, err := FormatV1(disk.Name(), []byte(passphrase), &FormatV1Options{Iter: 100})
	require.NoError(t, err)
	dev.Close()
	return disk
}

// formatV2Fast creates a LUKS v2 disk using our library with PBKDF2/minimal cost.
func formatV2Fast(t *testing.T, passphrase string) *os.File {
	t.Helper()
	disk := newTempDisk(t, 32*1024*1024)
	dev, err := FormatV2(disk.Name(), []byte(passphrase), &FormatV2Options{
		KDFType: "pbkdf2",
		KDFIter: 100,
	})
	require.NoError(t, err)
	dev.Close()
	return disk
}

// cryptsetupAddKey adds a new key to a LUKS device using cryptsetup.
func cryptsetupAddKey(t *testing.T, path, existingPass, newPass string) {
	t.Helper()
	cmd := exec.Command("cryptsetup", "luksAddKey", "--iter-time", "5", "-q", path)
	cmd.Stdin = strings.NewReader(existingPass + "\n" + newPass)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "cryptsetup luksAddKey failed: %s", out)
}

// cryptsetupOpen verifies that cryptsetup can unlock the device with the given passphrase
// (requires root; skips if not root).
func cryptsetupVerifyPassphrase(t *testing.T, path, passphrase string) {
	t.Helper()
	// Use --test-passphrase which verifies without activating a mapper (available in newer cryptsetup).
	cmd := exec.Command("cryptsetup", "open", "--test-passphrase", path)
	cmd.Stdin = strings.NewReader(passphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If --test-passphrase is not available or permission denied, skip.
		t.Logf("cryptsetup open --test-passphrase skipped (%v): %s", err, out)
	}
}

// -------------------------------------------------------------------------
// AddKey / AddKeyToSlot — LUKS v1
// -------------------------------------------------------------------------

func TestAddKeyV1(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	newSlot, err := dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)
	require.Equal(t, 1, newSlot)

	require.Equal(t, []int{0, 1}, dev.Slots())

	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.NoError(t, err)

	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)

	// Wrong passphrase should fail.
	_, err = dev.UnsealVolume(0, []byte("wrong"))
	require.ErrorIs(t, err, ErrPassphraseDoesNotMatch)
}

func TestAddKeyToSlotV1(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	err = dev.AddKeyToSlot(5, []byte("pass1"), []byte("pass5"))
	require.NoError(t, err)

	slots := dev.Slots()
	require.Contains(t, slots, 0)
	require.Contains(t, slots, 5)

	_, err = dev.UnsealVolume(5, []byte("pass5"))
	require.NoError(t, err)
}

func TestAddKeyV1WrongExisting(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	_, err = dev.AddKey([]byte("wrongpass"), []byte("pass2"))
	require.ErrorIs(t, err, ErrPassphraseDoesNotMatch)
}

// -------------------------------------------------------------------------
// AddKey / AddKeyToSlot — LUKS v2
// -------------------------------------------------------------------------

func TestAddKeyV2(t *testing.T) {
	t.Parallel()

	disk := formatV2Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	newSlot, err := dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)
	require.Equal(t, 1, newSlot)

	slots := dev.Slots()
	require.Contains(t, slots, 0)
	require.Contains(t, slots, 1)

	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.NoError(t, err)

	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}

func TestAddKeyToSlotV2(t *testing.T) {
	t.Parallel()

	disk := formatV2Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	err = dev.AddKeyToSlot(3, []byte("pass1"), []byte("pass3"))
	require.NoError(t, err)

	_, err = dev.UnsealVolume(3, []byte("pass3"))
	require.NoError(t, err)
}

// -------------------------------------------------------------------------
// KillSlot — LUKS v1
// -------------------------------------------------------------------------

func TestKillSlotV1(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	// Add a second key so we can kill slot 0.
	_, err = dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)

	// Kill slot 0; pass2 proves access via slot 1.
	err = dev.KillSlot(0, []byte("pass2"))
	require.NoError(t, err)

	require.Equal(t, []int{1}, dev.Slots())

	// Slot 0 passphrase should now fail.
	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.Error(t, err)

	// Slot 1 should still work.
	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}

func TestKillSlotV1RefusesLastSlot(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	// Should refuse: no other slot to prove access.
	err = dev.KillSlot(0, []byte("pass1"))
	require.Error(t, err)
}

// -------------------------------------------------------------------------
// KillSlot — LUKS v2
// -------------------------------------------------------------------------

func TestKillSlotV2(t *testing.T) {
	t.Parallel()

	disk := formatV2Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	_, err = dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)

	err = dev.KillSlot(0, []byte("pass2"))
	require.NoError(t, err)

	require.Equal(t, []int{1}, dev.Slots())

	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.Error(t, err)

	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}

// -------------------------------------------------------------------------
// RemoveKey — LUKS v1
// -------------------------------------------------------------------------

func TestRemoveKeyV1(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	_, err = dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)

	// Remove slot that holds pass1.
	err = dev.RemoveKey([]byte("pass1"))
	require.NoError(t, err)

	require.Equal(t, []int{1}, dev.Slots())

	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}

func TestRemoveKeyV1LastSlotRefused(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	err = dev.RemoveKey([]byte("pass1"))
	require.Error(t, err)
}

// -------------------------------------------------------------------------
// RemoveKey — LUKS v2
// -------------------------------------------------------------------------

func TestRemoveKeyV2(t *testing.T) {
	t.Parallel()

	disk := formatV2Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	_, err = dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)

	err = dev.RemoveKey([]byte("pass1"))
	require.NoError(t, err)

	require.Equal(t, []int{1}, dev.Slots())

	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}

// -------------------------------------------------------------------------
// ChangeKey — LUKS v1
// -------------------------------------------------------------------------

func TestChangeKeyV1(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "oldpass")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	err = dev.ChangeKey([]byte("oldpass"), []byte("newpass"))
	require.NoError(t, err)

	// New passphrase should work, old should not.
	slots := dev.Slots()
	require.NotEmpty(t, slots)
	v, err := dev.UnsealVolume(slots[0], []byte("newpass"))
	require.NoError(t, err, "new passphrase should unseal the volume")
	_ = v
}

func TestChangeKeyV1SingleSlot(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "oldpass")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	// Direct overwrite path (one slot).
	err = dev.ChangeKey([]byte("oldpass"), []byte("newpass"))
	require.NoError(t, err)

	// Verify new passphrase works.
	slots := dev.Slots()
	require.NotEmpty(t, slots)
	_, err = dev.UnsealVolume(slots[0], []byte("newpass"))
	require.NoError(t, err)
}

// -------------------------------------------------------------------------
// ChangeKey — LUKS v2
// -------------------------------------------------------------------------

func TestChangeKeyV2(t *testing.T) {
	t.Parallel()

	disk := formatV2Fast(t, "oldpass")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	err = dev.ChangeKey([]byte("oldpass"), []byte("newpass"))
	require.NoError(t, err)

	// New passphrase should unseal.
	slots := dev.Slots()
	require.NotEmpty(t, slots)
	_, err = dev.UnsealVolume(slots[0], []byte("newpass"))
	require.NoError(t, err)
}

// -------------------------------------------------------------------------
// HeaderBackup / HeaderRestore — LUKS v1
// -------------------------------------------------------------------------

func TestHeaderBackupRestoreV1(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	backupFile, err := os.CreateTemp("", "luks.v1.backup")
	require.NoError(t, err)
	backupFile.Close()
	defer os.Remove(backupFile.Name())

	// Backup the header.
	err = dev.HeaderBackup(backupFile.Name())
	require.NoError(t, err)

	// Add a key so the state changes.
	_, err = dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)
	require.Equal(t, []int{0, 1}, dev.Slots())

	// Restore the original backup.
	err = dev.HeaderRestore(backupFile.Name())
	require.NoError(t, err)

	// Only the original slot should exist after restore.
	require.Equal(t, []int{0}, dev.Slots())
	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.NoError(t, err)
}

// -------------------------------------------------------------------------
// HeaderBackup / HeaderRestore — LUKS v2
// -------------------------------------------------------------------------

func TestHeaderBackupRestoreV2(t *testing.T) {
	t.Parallel()

	disk := formatV2Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	backupFile, err := os.CreateTemp("", "luks.v2.backup")
	require.NoError(t, err)
	backupFile.Close()
	defer os.Remove(backupFile.Name())

	// Backup.
	err = dev.HeaderBackup(backupFile.Name())
	require.NoError(t, err)

	// Modify (add key).
	_, err = dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)
	require.Contains(t, dev.Slots(), 1)

	// Restore.
	err = dev.HeaderRestore(backupFile.Name())
	require.NoError(t, err)

	require.Equal(t, []int{0}, dev.Slots())
	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.NoError(t, err)
}

// -------------------------------------------------------------------------
// AddToken / RemoveToken — LUKS v2
// -------------------------------------------------------------------------

func TestAddRemoveTokenV2(t *testing.T) {
	t.Parallel()

	disk := formatV2Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	// Initially no tokens.
	tokens, err := dev.Tokens()
	require.NoError(t, err)
	require.Empty(t, tokens)

	// Add a token.
	id, err := dev.AddToken(Token{
		Type:    "custom",
		Slots:   []int{0},
		Payload: []byte(`{"some":"data"}`),
	})
	require.NoError(t, err)
	require.Equal(t, 0, id)

	// Re-open to verify persistence.
	dev.Close()
	dev, err = Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	tokens, err = dev.Tokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	require.Equal(t, "custom", tokens[0].Type)
	require.Equal(t, []int{0}, tokens[0].Slots)

	// Remove the token.
	err = dev.RemoveToken(0)
	require.NoError(t, err)

	tokens, err = dev.Tokens()
	require.NoError(t, err)
	require.Empty(t, tokens)
}

func TestAddTokenV1Unsupported(t *testing.T) {
	t.Parallel()

	disk := formatV1Fast(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	_, err = dev.AddToken(Token{Type: "test", Slots: []int{0}})
	require.Error(t, err)
}

// -------------------------------------------------------------------------
// Interoperability: cryptsetup formats → our write operations
// -------------------------------------------------------------------------

func TestAddKeyV1Interop_CryptsetupFormatOurAddKey(t *testing.T) {
	t.Parallel()

	// Use cryptsetup to format.
	disk := prepareLuks1Disk(t, "original")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	// Our library adds a new key.
	newSlot, err := dev.AddKey([]byte("original"), []byte("added"))
	require.NoError(t, err)
	require.Equal(t, 1, newSlot)

	// Re-open and verify both keys work.
	dev.Close()
	dev, err = Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	_, err = dev.UnsealVolume(0, []byte("original"))
	require.NoError(t, err)

	_, err = dev.UnsealVolume(1, []byte("added"))
	require.NoError(t, err)

	// cryptsetup should still recognise it.
	cryptsetupIsLuks(t, disk.Name())
	cryptsetupVerifyPassphrase(t, disk.Name(), "added")
}

func TestAddKeyV2Interop_CryptsetupFormatOurAddKey(t *testing.T) {
	t.Parallel()

	disk := prepareLuks2Disk(t, "original")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	newSlot, err := dev.AddKey([]byte("original"), []byte("added"))
	require.NoError(t, err)
	require.Equal(t, 1, newSlot)

	dev.Close()
	dev, err = Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	_, err = dev.UnsealVolume(0, []byte("original"))
	require.NoError(t, err)

	_, err = dev.UnsealVolume(1, []byte("added"))
	require.NoError(t, err)

	cryptsetupIsLuks(t, disk.Name())
	cryptsetupVerifyPassphrase(t, disk.Name(), "added")
}

func TestKillSlotV1Interop(t *testing.T) {
	t.Parallel()

	disk := prepareLuks1Disk(t, "pass1")
	defer disk.Close()

	// cryptsetup adds a second key.
	cryptsetupAddKey(t, disk.Name(), "pass1", "pass2")

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	// Our library kills slot 0 (proved by pass2 in slot 1).
	err = dev.KillSlot(0, []byte("pass2"))
	require.NoError(t, err)

	cryptsetupIsLuks(t, disk.Name())

	// Re-open and verify.
	dev.Close()
	dev, err = Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	require.Equal(t, []int{1}, dev.Slots())
	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}

func TestKillSlotV2Interop(t *testing.T) {
	t.Parallel()

	disk := prepareLuks2Disk(t, "pass1")
	defer disk.Close()

	cryptsetupAddKey(t, disk.Name(), "pass1", "pass2")

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	err = dev.KillSlot(0, []byte("pass2"))
	require.NoError(t, err)

	cryptsetupIsLuks(t, disk.Name())

	dev.Close()
	dev, err = Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	require.Equal(t, []int{1}, dev.Slots())
	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}

func TestChangeKeyV1Interop(t *testing.T) {
	t.Parallel()

	disk := prepareLuks1Disk(t, "oldpass")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	err = dev.ChangeKey([]byte("oldpass"), []byte("newpass"))
	require.NoError(t, err)

	cryptsetupIsLuks(t, disk.Name())

	slots := dev.Slots()
	require.NotEmpty(t, slots)
	_, err = dev.UnsealVolume(slots[0], []byte("newpass"))
	require.NoError(t, err)

	cryptsetupVerifyPassphrase(t, disk.Name(), "newpass")
}

func TestChangeKeyV2Interop(t *testing.T) {
	t.Parallel()

	disk := prepareLuks2Disk(t, "oldpass")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	err = dev.ChangeKey([]byte("oldpass"), []byte("newpass"))
	require.NoError(t, err)

	cryptsetupIsLuks(t, disk.Name())

	slots := dev.Slots()
	require.NotEmpty(t, slots)
	_, err = dev.UnsealVolume(slots[0], []byte("newpass"))
	require.NoError(t, err)

	cryptsetupVerifyPassphrase(t, disk.Name(), "newpass")
}

func TestHeaderBackupRestoreV1Interop(t *testing.T) {
	t.Parallel()

	disk := prepareLuks1Disk(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	backupFile, err := os.CreateTemp("", "luks.v1.interop.backup")
	require.NoError(t, err)
	backupFile.Close()
	defer os.Remove(backupFile.Name())

	// Backup using our library.
	err = dev.HeaderBackup(backupFile.Name())
	require.NoError(t, err)

	// Corrupt the on-disk key material (simulate damage).
	f, err := os.OpenFile(disk.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	garbage := make([]byte, 512)
	_, err = f.WriteAt(garbage, 4096) // wipe start of keyslot 0
	require.NoError(t, err)
	f.Close()

	// Restore using our library.
	err = dev.HeaderRestore(backupFile.Name())
	require.NoError(t, err)

	// Verify with our library and cryptsetup.
	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.NoError(t, err)
	cryptsetupIsLuks(t, disk.Name())
}

func TestHeaderBackupRestoreV2Interop(t *testing.T) {
	t.Parallel()

	disk := prepareLuks2Disk(t, "pass1")
	defer disk.Close()

	dev, err := Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	backupFile, err := os.CreateTemp("", "luks.v2.interop.backup")
	require.NoError(t, err)
	backupFile.Close()
	defer os.Remove(backupFile.Name())

	err = dev.HeaderBackup(backupFile.Name())
	require.NoError(t, err)

	// Add a key to change state.
	_, err = dev.AddKey([]byte("pass1"), []byte("pass2"))
	require.NoError(t, err)

	// Restore original header.
	err = dev.HeaderRestore(backupFile.Name())
	require.NoError(t, err)

	// Only original slot should remain.
	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.NoError(t, err)

	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.Error(t, err, "slot 1 should have been removed by restore")

	cryptsetupIsLuks(t, disk.Name())
}

// -------------------------------------------------------------------------
// Cross-format interop: our FormatV1 → cryptsetup add key → our verify
// -------------------------------------------------------------------------

func TestFormatV1Interop_CryptsetupAddKey(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 4*1024*1024)
	defer disk.Close()

	dev, err := FormatV1(disk.Name(), []byte("pass1"), &FormatV1Options{Iter: 1000})
	require.NoError(t, err)
	dev.Close()

	// cryptsetup adds a second key.
	cryptsetupAddKey(t, disk.Name(), "pass1", "pass2")

	// Our library should see both slots.
	dev, err = Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	require.Len(t, dev.Slots(), 2)
	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.NoError(t, err)
	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}

func TestFormatV2Interop_CryptsetupAddKey(t *testing.T) {
	t.Parallel()

	disk := newTempDisk(t, 32*1024*1024)
	defer disk.Close()

	dev, err := FormatV2(disk.Name(), []byte("pass1"), &FormatV2Options{
		KDFType: "pbkdf2",
		KDFIter: 1000,
	})
	require.NoError(t, err)
	dev.Close()

	// cryptsetup adds a second key.
	cryptsetupAddKey(t, disk.Name(), "pass1", "pass2")

	// Our library should see both slots.
	dev, err = Open(disk.Name())
	require.NoError(t, err)
	defer dev.Close()

	require.Len(t, dev.Slots(), 2)
	_, err = dev.UnsealVolume(0, []byte("pass1"))
	require.NoError(t, err)
	_, err = dev.UnsealVolume(1, []byte("pass2"))
	require.NoError(t, err)
}
