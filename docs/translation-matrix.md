# Implementation and OSS adapter matrix

This project uses Node.js where it is a good fit and delegates mature forensic or specialized cryptographic work to established local OSS tools.

| Capability | Implementation | Why |
| --- | --- | --- |
| Machine/device inventory and safety checks | Node.js plus `lsblk`/`findmnt` | Auditable argument-array orchestration and Linux kernel truth |
| Evidence imaging | GNU ddrescue | Resumable mapfile and damaged-media behavior |
| Deleted filesystem metadata/files | The Sleuth Kit `fls` and `tsk_recover`; optional `ntfsundelete` | Mature filesystem parsers and deleted-record semantics |
| Filesystem-unallocated stream | The Sleuth Kit `blkls -A` | Filesystem-aware free-block selection |
| Signature carving | PhotoRec over the unallocated-only stream emitted by `blkls` | Broad signature library without exposing allocated source bytes to the carver |
| Shadow copies and BitLocker views | libvshadow and dislocker, reviewed read-only mounting | Specialized on-disk formats and mount lifecycle |
| Residual-memory feature extraction | bulk_extractor | Mature scanners and hibernation support |
| Streaming candidate discovery, strict validation, deduplication, manifests, artifacts | Native Node.js | Portable binary/text handling and controlled local output |
| BIP-39 wordlists/checksums | `@scure/bip39` | Small audited implementation; no wallet or network dependency |
| PEM/DER/CNG consistency and derived public keys | Node.js `crypto` | Local OpenSSL-backed parsing and round trips |
| DPAPI structure discovery | Native Node.js | Safe offline parsing during broad scans |
| DPAPI password derivation/decryption | Optional local Impacket bridge | Avoid duplicating specialized authenticated cryptography |

No adapter uploads evidence or tests credentials online. External commands are spawned with `shell: false`; secret-bearing operations use protected files rather than command-line values.

Primary upstream documentation:

- [GNU ddrescue manual](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [The Sleuth Kit tools](https://www.sleuthkit.org/sleuthkit/docs.php)
- [PhotoRec scripted operation](https://www.cgsecurity.org/wiki/Scripted_run)
- [Fortra Impacket](https://github.com/fortra/impacket)
- [bulk_extractor](https://github.com/simsong/bulk_extractor)
- [libvshadow](https://github.com/libyal/libvshadow)
- [dislocker](https://github.com/Aorimn/dislocker)
