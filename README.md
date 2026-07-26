# Pure Go library for LUKS volume management

`luks.go` is a pure-Go library for working with LUKS-encrypted volumes.

This library focuses on the read-only (unlocking) path — it reads LUKS metadata and
recovers volume keys without modifying the LUKS header.

## Installation

```
go get github.com/anatol/luks.go
```

Requires Linux (uses device-mapper via `/dev/mapper`).

## Supported features

- LUKS v1 and LUKS v2
- Detached headers (`OpenWithHeader`)
- KDFs: `pbkdf2`, `argon2i`, `argon2id`
- Ciphers: AES, Camellia, Twofish (XTS mode)
- Hash algorithms: SHA-1/224/256/384/512, SHA-3, RIPEMD-160, BLAKE2b, BLAKE2s, Whirlpool
- dm-crypt flags: allow-discards, same-cpu-crypt, submit-from-crypt-cpus, no-read-workqueue, no-write-workqueue
- Token metadata (clevis, systemd-fido2, etc.)
- LUKS v2 keyslot priorities
- Multi-segment LUKS2 layouts (e.g. integrity)
- TCG OPAL self-encrypting drives (cryptsetup `--hw-opal` and `--hw-opal-only`
  segments): the locking range is unlocked through the kernel SED interface
  (`CONFIG_BLK_SED_OPAL`) and mapped with dm-linear or dm-crypt; active
  devices carry the same `CRYPT-LUKS2-OPAL-...` dm UUID as cryptsetup

Note: LUKS2 mandatory requirements are enforced at unseal time. Devices whose
header carries a requirement this library does not implement (e.g.
`online-reencrypt-v2` while a re-encryption is in progress) are refused,
matching cryptsetup's behavior.

## Usage

### Open and unlock

```go
dev, err := luks.Open("/dev/sda1")
if err != nil {
    log.Fatal(err)
}
defer dev.Close()

// Unlock a specific slot and create a device mapper entry.
// Equivalent to: cryptsetup open /dev/sda1 volumename
if err := dev.Unlock(0, []byte("password"), "volumename"); err == luks.ErrPassphraseDoesNotMatch {
    log.Fatal("wrong password")
} else if err != nil {
    log.Fatal(err)
}
// /dev/mapper/volumename is now available

// Close the mapper when done.
// Equivalent to: cryptsetup close volumename
if err := luks.Lock("volumename"); err != nil {
    log.Fatal(err)
}
```

### Try all keyslots

```go
if err := dev.UnlockAny([]byte("password"), "volumename"); err != nil {
    log.Fatal(err)
}
```

### Detached header

```go
dev, err := luks.OpenWithHeader("/dev/sda1", "/path/to/header.bin")
```

### Flags (dm-crypt options)

```go
// Set flags before unlocking
dev.FlagsAdd(luks.FlagAllowDiscards)
dev.FlagsAdd(luks.FlagNoReadWorkqueue, luks.FlagNoWriteWorkqueue)

// Get current flags
flags := dev.FlagsGet()

// Clear all flags
dev.FlagsClear()
```

Available flags:
- `FlagAllowDiscards` — pass discard/TRIM requests through (SSD-friendly, reduces security)
- `FlagSameCPUCrypt` — perform encryption on the same CPU as the IO
- `FlagSubmitFromCryptCPUs` — submit IO from crypto CPUs
- `FlagNoReadWorkqueue` — bypass read workqueue (Linux 5.9+)
- `FlagNoWriteWorkqueue` — bypass write workqueue (Linux 5.9+)

### Two-step unlock (advanced)

`UnsealVolume` recovers the key without activating the mapper, allowing inspection or
custom dm-crypt setup:

```go
volume, err := dev.UnsealVolume(0, []byte("password"))
if err == luks.ErrPassphraseDoesNotMatch {
    log.Fatal("wrong password")
} else if err != nil {
    log.Fatal(err)
}

// volume contains encryption parameters; activate when ready
if err := volume.SetupMapper("volumename"); err != nil {
    log.Fatal(err)
}
```

### Token metadata

Tokens are LUKS v2 metadata entries (or luksmeta entries for LUKS v1) that carry
supplementary information for unlocking tools like clevis or systemd-fido2.

```go
tokens, err := dev.Tokens()
for _, t := range tokens {
    fmt.Printf("token %d: type=%s slots=%v\n", t.ID, t.Type, t.Slots)
    // t.Payload contains the raw JSON (LUKS v2) or binary (LUKS v1) token data
}
```

### Device metadata

```go
fmt.Println(dev.Version()) // 1 or 2
fmt.Println(dev.UUID())
fmt.Println(dev.Slots()) // active keyslot IDs, sorted by priority (LUKS v2)
fmt.Println(dev.Path())
```

## How it works

The unlock process follows these steps for both LUKS v1 and v2:

1. **Open** — read and validate the binary header (magic bytes, version, checksum).
   For LUKS v2, the JSON metadata area is also parsed.
2. **Key derivation** — derive an intermediate key from the passphrase using the
   keyslot's KDF (PBKDF2 for v1; PBKDF2, Argon2i, or Argon2id for v2).
3. **Keyslot decryption** — decrypt the keyslot area sector-by-sector using
   XTS-mode encryption with the derived key.
4. **Anti-forensic merge** — recover the volume master key from 4000 stripes
   using the AFsplit/AFmerge algorithm (hash-based diffusion + XOR chain).
5. **Digest verification** — re-derive a digest from the recovered key and compare
   it against the stored digest to confirm the passphrase is correct.
6. **Device mapper setup** — pass the recovered key and encryption parameters to
   the Linux device mapper (dm-crypt) to create the decrypted block device.

## References

- [LUKS v1 on-disk format (PDF)](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf)
- [LUKS v2 on-disk format (PDF)](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/on-disk-format-luks2.pdf)
- [luksmeta (LUKS v1 token metadata)](https://github.com/latchset/luksmeta)

## License

See [LICENSE](LICENSE).
