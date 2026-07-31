# Optional Impacket DPAPI bridge

The Node layer locates and structurally validates DPAPI blobs and recovered DPAPI master-key files. Password-based Windows DPAPI key derivation and authenticated decryption are delegated to the audited Impacket implementation because reimplementing that cryptography in the orchestrator would add avoidable risk.

Install the Ubuntu package:

```bash
sudo apt install python3-impacket
```

The bridge reads every secret from a bounded, stable regular file, rejects symbolic-link path components and known network-backed filesystems, never accepts secret values on the command line, and writes decrypted bytes to a new mode-`0600` file. It rechecks the output mount while writing and prints only status metadata. Run it offline.

## Decrypt a master-key file

Recovered user master keys usually came from a Windows profile’s `Microsoft/Protect/<SID>/` directory. Supply the matching SID and a protected password file:

```bash
umask 077
python3 optional/impacket/dpapi_bridge.py masterkey \
  --masterkey-file /case/artifacts/recovered-masterkey \
  --sid 'S-1-5-21-...' \
  --password-file /case/protected/windows-password.txt \
  --output /case/protected/decrypted-masterkey.bin
```

An NT hash or SHA-1 user key can be supplied in a protected hex file with `--user-hash-file`. A raw recovered DPAPI system key can be supplied with `--system-key-file`; that mode does not use a SID.

## Unprotect a blob

Use the resulting raw master key to authenticate and decrypt a recovered blob. Optional entropy, when an application used it, must also come from a file:

```bash
python3 optional/impacket/dpapi_bridge.py unprotect \
  --blob /case/artifacts/finding-000123/value.dpapi \
  --master-key-file /case/protected/decrypted-masterkey.bin \
  --output /case/protected/unprotected.bin
```

For a Chromium Local State `encrypted_key`, the miner writes a `decoded-dpapi-blob.bin` derived artifact that can be used as `--blob`.

The bridge refuses to overwrite an existing output. A successful decryption means the DPAPI signature authenticated; it does not decide how an application encoded the decrypted payload.

Upstream reference: [Fortra Impacket](https://github.com/fortra/impacket).
