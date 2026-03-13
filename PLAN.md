# LUKS Write Operations — Implementation Plan

## Goal
Add full write-operation support to the `luks.go` library so it can do everything the most common `cryptsetup` commands do, for both LUKS v1 and v2. All produced volumes must be interoperable with `cryptsetup`.

## Cryptsetup commands to cover

| cryptsetup command | Operation | Scope |
|---|---|---|
| `luksFormat --type luks1` | Create new LUKS v1 device | standalone `FormatV1()` |
| `luksFormat --type luks2` | Create new LUKS v2 device | standalone `FormatV2()` |
| `luksAddKey` | Add a new passphrase/keyslot | `Device.AddKey()` |
| `luksKillSlot` | Destroy a keyslot by index | `Device.KillSlot()` |
| `luksRemoveKey` | Destroy first keyslot matching passphrase | `Device.RemoveKey()` |
| `luksChangeKey` | Replace passphrase in matching slot | `Device.ChangeKey()` |
| `luksHeaderBackup` | Dump header to file | `Device.HeaderBackup()` |
| `luksHeaderRestore` | Restore header from file | `Device.HeaderRestore()` |
| Token add/remove (v2) | Manage LUKS v2 JSON tokens | `Device.AddToken()` / `Device.RemoveToken()` |

---

## API Design

### New `Device` interface methods (luks.go)

```go
// AddKey adds a new keyslot encrypted with newPassphrase.
// existingPassphrase must match any existing slot to prove authority.
// Returns the new slot ID.
AddKey(existingPassphrase, newPassphrase []byte) (int, error)

// AddKeyToSlot is like AddKey but insists on a specific slot index.
AddKeyToSlot(slot int, existingPassphrase, newPassphrase []byte) error

// KillSlot wipes keyslot slot. At least one other slot must remain.
// passphrase must match a *different* slot (guards against locking out).
KillSlot(slot int, passphrase []byte) error

// RemoveKey finds and wipes the first slot whose passphrase matches.
RemoveKey(passphrase []byte) error

// ChangeKey replaces the passphrase in whichever slot holds existingPassphrase.
ChangeKey(existingPassphrase, newPassphrase []byte) error

// HeaderBackup writes a complete header backup to path.
HeaderBackup(path string) error

// HeaderRestore replaces the on-disk header with the contents of path.
// WARNING: all key material not present in the backup is permanently lost.
HeaderRestore(path string) error

// AddToken adds a LUKS v2 JSON token; returns the new token ID.
// Returns an error on LUKS v1 (not supported).
AddToken(t Token) (int, error)

// RemoveToken deletes the LUKS v2 token with the given ID.
// Returns an error on LUKS v1.
RemoveToken(id int) error
```

### New standalone functions (format.go)

```go
// FormatV1 writes a LUKS v1 header to an existing block device / file.
// The device must already exist and be large enough.
// Returns an open Device on success.
func FormatV1(path string, passphrase []byte, opts *FormatV1Options) (Device, error)

// FormatV2 writes a LUKS v2 header to an existing block device / file.
func FormatV2(path string, passphrase []byte, opts *FormatV2Options) (Device, error)

type FormatV1Options struct {
    UUID       string // auto-generated if empty
    Cipher     string // default "aes"
    CipherMode string // default "xts-plain64"
    Hash       string // default "sha256"
    MasterKeySize int // bytes; default 32 (AES-128-XTS / 256-bit volume key)
    Iter       int    // PBKDF2 iterations; 0 → use IterTime
    IterTime   int    // ms; default 2000 (used only when Iter==0)
}

type FormatV2Options struct {
    UUID          string  // auto-generated if empty
    Label         string
    Cipher        string  // default "aes"
    CipherMode    string  // default "xts-plain64"
    SectorSize    int     // default 512
    MasterKeySize int     // bytes; default 64 (AES-256-XTS / 512-bit volume key)
    KDFType       string  // "argon2id"|"argon2i"|"pbkdf2"; default "argon2id"
    KDFHash       string  // default "sha256"
    // PBKDF2
    KDFIter       int
    // Argon2
    KDFTime       uint32  // default 4
    KDFMemory     uint32  // KiB; default 1048576 (1 GiB)
    KDFCPUs       uint8   // default 4
}
```

### AddKeyOptions

```go
type AddKeyOptions struct {
    Slot      int    // -1 = auto; for AddKey it is ignored, for AddKeyToSlot it is required
    KDFType   string // default: inherit from slot 0
    KDFHash   string
    KDFIter   int
    KDFTime   uint32
    KDFMemory uint32
    KDFCPUs   uint8
}
```

---

## File structure after implementation

| File | Contents |
|---|---|
| `luks.go` | Add new interface methods; add `FormatV1Options`, `FormatV2Options` |
| `format.go` | `FormatV1`, `FormatV2` implementations |
| `luks1.go` | Add `AddKey`, `AddKeyToSlot`, `KillSlot`, `RemoveKey`, `ChangeKey`, `HeaderBackup`, `HeaderRestore`, `AddToken`, `RemoveToken` on `deviceV1` |
| `luks2.go` | Same on `deviceV2` + helper `flushMetadata` |
| `format_test.go` | Tests for `FormatV1` and `FormatV2` |
| `write_test.go` | Tests for all write methods (both self-tests and cryptsetup interop) |

---

## Implementation Tasks (execute in order)

### Task 1 — Extend `Device` interface + option types
- Add all new methods to the `Device` interface in `luks.go`
- Add `FormatV1Options`, `FormatV2Options` structs
- Add stub implementations on `deviceV1` and `deviceV2` returning `ErrNotImplemented`

### Task 2 — `FormatV1`
Implement `FormatV1(path, passphrase, opts)`:
1. Fill defaults in opts.
2. Generate random volume master key.
3. Generate random UUID (unless provided).
4. Compute MkDigestSalt (32 random bytes) + MkDigest (PBKDF2, SHA-1 output = 20 bytes, as per spec).
5. Calibrate PBKDF2 iterations (or use opts.Iter) for keyslot 0.
6. Place keyslot 0: generate salt, derive AFKey, afSplit, encrypt, store.
7. Compute `PayloadOffset` = `roundUp(8 + 8 * keyslotSectors, 2048)` sectors.
8. Set `KeyMaterialOffset` for each slot (only slot 0 active, others zeroed).
9. Serialise `headerV1` with `binary.Write(BigEndian)` and write at offset 0.
10. Write encrypted keyslot material.
11. Open the file read-only and return a `Device`.

On-disk layout:
```
[0   – 591]     headerV1 (592 bytes)
[592 – 4095]    zeros (header padding to sector 8)
[4096 – ...]    keyslot 0 material  (KeyBytes × 4000 bytes, sector-aligned)
[4096 + n×ks – ...]  keyslots 1–7 (empty, but offsets stored in header)
[PayloadOffset×512 – end]  data
```

### Task 3 — `FormatV2`
Implement `FormatV2(path, passphrase, opts)`:
1. Fill defaults.
2. Generate master key + UUID.
3. Build `metadata` JSON:
   - Single segment `"0"`: type=crypt, offset=headerSize, iv_tweak=0, size=dynamic.
   - Single keyslot `"0"`: derive, AF-split, encrypt, area.offset=32768.
   - Digest `"0"`: pbkdf2 of master key.
   - Config: json_size=12288, keyslots_size=headerSize-32768.
4. Write primary binary header at offset 0 (checksum over zeroed checksum field using SHA-256).
5. Write primary JSON at offset 4096.
6. Write secondary binary header at offset headerSize/2 (different salt, same sequence ID=1).
7. Write secondary JSON at offset headerSize/2 + 4096.
8. Write keyslot material at area.offset.
9. Return an open Device.

Header defaults: headerSize = 16 MiB, json_size = 12288, keyslot area starts at 32768.

### Task 4 — `AddKey` / `AddKeyToSlot` on LUKS v1
File-writes needed: update `hdr.KeySlots[slot]` binary struct + write key material.
1. `UnsealVolume` with `existingPassphrase` to recover master key.
2. Find first free slot (or use specified slot).
3. Generate slot salt; calibrate/use given iter.
4. Derive AFKey, afSplit, encrypt.
5. Open header file O_RDWR, write key material, write updated header binary.
6. Refresh `d.hdr` in memory.

### Task 5 — `AddKey` / `AddKeyToSlot` on LUKS v2
1. Recover master key.
2. Allocate new slot ID, area offset (after last used area, 4096-aligned; skip secondary header region).
3. Update `d.meta.Keyslots`, add new keyslot entry, add to digest.Keyslots list.
4. Write key material.
5. Call `flushMetadata` (see below).

`flushMetadata` (LUKS v2 helper):
- Serialise `d.meta` to JSON, pad to json_size.
- Increment `d.hdr.SequenceID`.
- Recompute both header checksums (primary and secondary with their respective salts).
- Write primary header + JSON at 0.
- Write secondary header + JSON at headerSize/2.

### Task 6 — `KillSlot` / `RemoveKey` on LUKS v1
`KillSlot`:
1. Verify `passphrase` unlocks a *different* slot (ensures access remains).
2. Zero the keyslot material area on disk (cryptsetup also overwrites with random bytes; we zero for simplicity, add `crypto/rand` overwrite too).
3. Set `hdr.KeySlots[slot].Active = 0x0000DEAD` (LUKS_KEY_DISABLED).
4. Write updated header.

`RemoveKey`: find slot by trying `UnsealVolume` for each slot; call `KillSlot`.

### Task 7 — `KillSlot` / `RemoveKey` on LUKS v2
`KillSlot`:
1. Verify passphrase unlocks a different slot.
2. Zero key material at `area.Offset`.
3. Delete `d.meta.Keyslots[slot]`; remove from `digest.Keyslots`.
4. Call `flushMetadata`.

`RemoveKey`: iterate `d.Slots()`, try UnsealVolume, call `KillSlot`.

### Task 8 — `ChangeKey` on both versions
1. Recover master key with `existingPassphrase` (find which slot).
2. Calculate a free slot or use the same slot:
   - If `slotsCount > 1`: add new key first, then kill old slot. Safe swap.
   - If only one slot: overwrite it atomically (can't use safe swap; just overwrite).
3. For safety, prefer safe swap when possible.

### Task 9 — `HeaderBackup` / `HeaderRestore` on both versions
`HeaderBackup`:
- V1: copy bytes 0 to `PayloadOffset × 512 - 1` to `path`.
- V2: copy bytes 0 to `HeaderSize - 1` to `path`.

`HeaderRestore`:
- V1: write bytes from backup file to device at offset 0 up to backup length.
- V2: same; verify magic + version before writing.

### Task 10 — `AddToken` / `RemoveToken` on LUKS v2
`AddToken`:
- Find next free token ID.
- Validate `Token.Slots` exist.
- Marshal token to JSON with `type` + `keyslots` + payload fields merged.
- Add to `d.meta.Tokens`, call `flushMetadata`.

`RemoveToken`:
- Delete from `d.meta.Tokens`, call `flushMetadata`.

For LUKS v1, both methods return `fmt.Errorf("token operations not supported on LUKS v1")`.

### Task 11 — Tests: self-verification
File `format_test.go` and `write_test.go`:
- `TestFormatV1Basic`: format, open, unseal.
- `TestFormatV1MultipleOptions`: different hash/cipher/iter combos.
- `TestFormatV2Basic`: format, open, unseal.
- `TestFormatV2Argon2Options`: test argon2i, argon2id, pbkdf2 variants.
- `TestAddKeyV1` / `TestAddKeyV2`: add key, verify both passphrases work.
- `TestKillSlotV1` / `TestKillSlotV2`: kill slot, verify old passphrase fails.
- `TestRemoveKeyV1` / `TestRemoveKeyV2`.
- `TestChangeKeyV1` / `TestChangeKeyV2`.
- `TestHeaderBackupRestoreV1` / `TestHeaderBackupRestoreV2`.
- `TestAddRemoveTokenV2`.

### Task 12 — Tests: cryptsetup interoperability
- `TestFormatV1Interop`: our `FormatV1` → cryptsetup `luksOpen` + `luksDump`.
- `TestFormatV2Interop`: our `FormatV2` → cryptsetup verify.
- `TestAddKeyV1Interop`: cryptsetup `luksFormat` → our `AddKey` → cryptsetup `luksOpen` with new passphrase.
- `TestAddKeyV2Interop`: same for v2.
- `TestKillSlotInterop`: cryptsetup `luksFormat` + `luksAddKey` → our `KillSlot` → cryptsetup verify only remaining slot works.
- `TestChangeKeyInterop`: our `ChangeKey` → cryptsetup verify.
- `TestHeaderBackupRestoreInterop`: cryptsetup format → our backup → wipe header → our restore → cryptsetup open.

### Task 13 — Update README
Add "Write Operations" section documenting all new API functions with examples.

---

## Key implementation notes

### LUKS v1 on-disk constants
- Magic: `LUKS\xba\xbe`
- Version: 1
- Keyslot ENABLED: `0x00AC71F3`
- Keyslot DISABLED: `0x0000DEAD`
- stripesNum: 4000
- keyslot sector start: 8 (byte 4096)
- `PayloadOffset` (sectors) = `roundUp(8 + nSlots × ksSectors, 2048)` where `ksSectors = roundUp(KeyBytes × 4000, 512) / 512`

### LUKS v2 JSON layout
- headerSize = 16 MiB = 16777216
- json_size = 12288
- keyslots_size = headerSize − 32768 = 16744448
- Keyslot area 0 starts at byte 32768
- Secondary header at byte headerSize/2 = 8388608
- Data segment at byte headerSize = 16777216
- Checksum: SHA-256 of entire 4096-byte binary header with Checksum field zeroed

### File access pattern for write methods
Write methods open `d.hdrF.Name()` with `os.OpenFile(path, os.O_RDWR, 0)` for their operation, separate from the read-only handle stored in `d.hdrF`. This keeps backward compatibility (Open remains read-only) while allowing writes.

### Security
- Always overwrite freed keyslot material with random bytes before clearing the header entry.
- Use `clearSlice()` for all in-memory key material.
- Validate at least one active slot remains before killing a slot.

---

## Execution order
1. Task 1 (interface + stubs) — unblocks compilation
2. Task 2 (FormatV1)
3. Task 11 FormatV1 tests (write + verify loop)
4. Task 3 (FormatV2)
5. Task 11 FormatV2 tests
6. Task 4 (AddKey v1)
7. Task 5 (AddKey v2)
8. Task 6 (KillSlot/RemoveKey v1)
9. Task 7 (KillSlot/RemoveKey v2)
10. Task 8 (ChangeKey v1+v2)
11. Task 9 (HeaderBackup/Restore)
12. Task 10 (AddToken/RemoveToken v2)
13. Task 11 remaining tests
14. Task 12 interop tests
15. Task 13 README
