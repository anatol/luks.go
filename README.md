# Pure Go library for LUKS volume management

`luks.go` is a pure-Go library that helps to deal with LUKS-encrypted volumes.

Currently, this library is focusing on the read-only path i.e. unlocking a partition without doing
any modifications to LUKS metadata header.

Here is an example that demonstrates the API usage:
```go
dev, err := luks.Open("/dev/sda1")
if err != nil {
  // handle error
}
defer dev.Close()

// set LUKS flags before unlocking the volume
if err := dev.FlagsAdd(luks.FlagAllowDiscards); err != nil {
    log.Print(err)
}

// UnsealVolume+SetupMapper is equivalent of `cryptsetup open /dev/sda1 volumename`
volume, err = dev.UnsealVolume(/* slot */ 0, []byte("password"))
if err == luks.ErrPassphraseDoesNotMatch {
    log.Printf("The password is incorrect")
} else if err != nil {
    log.Print(err)
} else {
    err := volume.SetupMapper("volumename")
    // at this point system should have a file `/dev/mapper/volumename`.
}

// equivalent of `cryptsetup close volumename`
if err := luks.Lock("volumename"); err != nil {
    log.Print(err)
}
```

## License

See [LICENSE](LICENSE).
