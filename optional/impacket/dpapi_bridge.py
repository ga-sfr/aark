#!/usr/bin/env python3
"""Offline DPAPI bridge for operations best delegated to Impacket.

Secret inputs are read from files, decrypted bytes are written to a new mode-0600
file, and stdout contains status metadata only. Nothing is sent over a network.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from hashlib import pbkdf2_hmac

try:
    from Cryptodome.Hash import HMAC, MD4, SHA1
    from impacket.dpapi import DPAPI_BLOB, MasterKey, MasterKeyFile
except ImportError as error:  # pragma: no cover - depends on an optional system package
    raise SystemExit("python3-impacket is required for this optional bridge") from error


_NETWORK_FILESYSTEMS = {
    "9p", "afs", "ceph", "cifs", "davfs", "glusterfs", "lustre", "nfs", "nfs4", "smb3", "virtiofs"
}
_LOCAL_FUSE_FILESYSTEMS = {
    "fuse.dislocker", "fuse.exfat", "fuse.ntfs", "fuse.ntfs-3g", "fuseblk",
}


class SafeArgumentParser(argparse.ArgumentParser):
    """Avoid echoing sensitive local paths from parser errors by default."""

    def error(self, _message: str) -> None:
        raise ValueError("invalid command-line arguments; use --help for the file-only interface")


def _unescape_mount(value: str) -> str:
    return value.replace(r"\040", " ").replace(r"\011", "\t").replace(r"\012", "\n").replace(r"\134", "\\")


def _nearest_existing(value: pathlib.Path) -> pathlib.Path:
    current = pathlib.Path(os.path.abspath(value))
    while True:
        try:
            os.lstat(current)
            return current
        except FileNotFoundError:
            parent = current.parent
            if parent == current:
                raise ValueError("no existing parent could be resolved for a protected path")
            current = parent


def _mount_for(value: pathlib.Path) -> tuple[str, str, str]:
    resolved = os.path.abspath(value)
    selected: tuple[str, str, str] | None = None
    with open("/proc/self/mounts", "r", encoding="utf-8") as mounts_file:
        for line in mounts_file:
            fields = line.rstrip("\n").split(" ")
            if len(fields) < 4:
                continue
            source, target, filesystem = (_unescape_mount(fields[index]) for index in range(3))
            prefix = "/" if target == "/" else target.rstrip("/") + "/"
            if resolved == target or resolved.startswith(prefix):
                candidate = (source, target, filesystem.lower())
                # Later records are the visible topmost layer for stacked mounts.
                if selected is None or len(target) >= len(selected[1]):
                    selected = candidate
    if selected is None:
        raise ValueError("could not determine the local mount backing a protected path")
    return selected


def _assert_local_path(value: pathlib.Path, label: str) -> tuple[str, str, str]:
    record = _mount_for(_nearest_existing(value))
    source, _target, filesystem = record
    network = (
        filesystem in _NETWORK_FILESYSTEMS
        or ((filesystem == "fuse" or filesystem.startswith("fuse.")) and filesystem not in _LOCAL_FUSE_FILESYSTEMS)
        or source.startswith("//")
        or re.match(r"^/dev/(?:nbd|rbd)", source) is not None
    )
    if network:
        raise ValueError(f"{label} must not be on a network-backed filesystem")
    if source.startswith("/dev/") and _block_source_is_network(source):
        raise ValueError(f"{label} must not be on a network-backed block transport")
    return record


def _block_source_is_network(source: str) -> bool:
    command = [
        "/usr/bin/lsblk", "--inverse", "--json", "--paths", "--output", "PATH,TYPE,TRAN,SUBSYSTEMS",
        re.sub(r"\[[^\]]*\]$", "", source),
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        if len(completed.stdout) > 64 * 1024:
            raise ValueError("block-transport inventory exceeded its bounded output limit")
        document = json.loads(completed.stdout.decode("utf-8")) if completed.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
        document = None
    if not isinstance(document, dict):
        raise ValueError("could not safely resolve the block transport backing a protected path")
    pending = document.get("blockdevices")
    if not isinstance(pending, list):
        raise ValueError("could not safely resolve the block transport backing a protected path")
    disks: list[dict[str, object]] = []
    while pending:
        node = pending.pop()
        if not isinstance(node, dict):
            continue
        if node.get("type") == "disk" and isinstance(node.get("path"), str):
            disks.append(node)
        children = node.get("children")
        if isinstance(children, list):
            pending.extend(children)
    if not disks:
        raise ValueError("could not safely identify the physical device backing a protected path")
    network_transports = {"iscsi", "fcoe", "aoe", "tcp", "rdma"}
    return any(
        str(node.get("tran", "")).lower() in network_transports
        or bool({"iscsi", "fcoe", "aoe", "nvme-fabrics", "nbd", "rbd", "drbd"}.intersection(str(node.get("subsystems", "")).lower().split(":")))
        or re.match(r"^/dev/(?:nbd|rbd|drbd)", str(node.get("path", ""))) is not None
        for node in disks
    )


def _assert_no_symlink_components(value: pathlib.Path) -> None:
    absolute = pathlib.Path(os.path.abspath(value))
    current = pathlib.Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"symbolic-link path component is not allowed: {current}")


def _read_bounded(source: pathlib.Path, maximum: int, label: str) -> bytes:
    expected_path = os.path.abspath(source)
    _assert_no_symlink_components(source)
    mount_before = _assert_local_path(source, label)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"{label} must be a single-link regular, non-symbolic-link file")
        if before.st_size < 0 or before.st_size > maximum:
            raise ValueError(f"{label} exceeds its {maximum}-byte safety limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            value = handle.read(maximum + 1)
        if len(value) > maximum:
            raise ValueError(f"{label} exceeds its {maximum}-byte safety limit")
        after = os.fstat(descriptor)
        current = os.lstat(source)
        if (
            len(value) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or os.path.realpath(f"/proc/self/fd/{descriptor}") != expected_path
            or os.path.realpath(source) != expected_path
            or _assert_local_path(source, label) != mount_before
        ):
            raise ValueError(f"{label} changed while it was being read")
        return value
    finally:
        os.close(descriptor)


def _private_no_clobber_write(destination: pathlib.Path, value: bytes) -> None:
    destination = pathlib.Path(os.path.abspath(destination))
    expected_path = os.path.abspath(destination)
    _assert_no_symlink_components(destination)
    mount_before = _assert_local_path(destination, "output")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _assert_no_symlink_components(destination)
    if _assert_local_path(destination, "output") != mount_before:
        raise ValueError("output mount changed while its directory was being created")
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    opened = os.fstat(descriptor)
    try:
        current = os.lstat(destination)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_nlink != 1
            or current.st_nlink != 1
            or os.path.realpath(f"/proc/self/fd/{descriptor}") != expected_path
            or os.path.realpath(destination) != expected_path
        ):
            raise ValueError("output path changed immediately after protected creation")
        if _assert_local_path(destination, "output") != mount_before:
            raise ValueError("output mount changed immediately before decrypted bytes were written")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        if _assert_local_path(destination, "output") != mount_before:
            raise ValueError("output mount changed while decrypted bytes were being written")
        current = os.lstat(destination)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or os.path.realpath(destination) != expected_path
        ):
            raise ValueError("output path changed while decrypted bytes were being written")
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            try:
                os.fsync(directory)
            except OSError as error:
                if error.errno not in (errno.EINVAL, errno.ENOSYS, errno.ENOTSUP):
                    raise
        finally:
            os.close(directory)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            current = os.lstat(destination)
            if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                destination.unlink()
        except FileNotFoundError:
            pass
        raise


def _password(path: pathlib.Path) -> str:
    value = _read_bounded(path, 1024 * 1024, "password file")
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    return value.decode("utf-8", errors="strict")


def _hex_key(path: pathlib.Path) -> bytes:
    encoded = b"".join(_read_bounded(path, 4096, "user-hash file").split())
    if len(encoded) not in (32, 40) or any(byte not in b"0123456789abcdefABCDEF" for byte in encoded):
        raise ValueError("user-hash file must contain one 16-byte NT hash or 20-byte SHA-1 hash in hex")
    return bytes.fromhex(encoded.decode("ascii"))


def _user_keys_from_password(sid: str, password: str) -> list[bytes]:
    sid_bytes = (sid + "\0").encode("utf-16le")
    password_bytes = password.encode("utf-16le")
    sha1_password = SHA1.new(password_bytes).digest()
    nt_hash = MD4.new(password_bytes).digest()
    protected_stage1 = pbkdf2_hmac("sha256", nt_hash, sid.encode("utf-16le"), 10_000)
    protected_stage2 = pbkdf2_hmac("sha256", protected_stage1, sid.encode("utf-16le"), 1)[:16]
    return [
        HMAC.new(protected_stage2, sid_bytes, SHA1).digest()[:20],
        HMAC.new(nt_hash, sid_bytes, SHA1).digest(),
        HMAC.new(sha1_password, sid_bytes, SHA1).digest(),
    ]


def _user_keys_from_hash(sid: str, value: bytes) -> list[bytes]:
    sid_bytes = (sid + "\0").encode("utf-16le")
    keys = [HMAC.new(value, sid_bytes, SHA1).digest()]
    if len(value) == 16:
        protected_stage1 = pbkdf2_hmac("sha256", value, sid.encode("utf-16le"), 10_000)
        protected_stage2 = pbkdf2_hmac("sha256", protected_stage1, sid.encode("utf-16le"), 1)[:16]
        keys.insert(0, HMAC.new(protected_stage2, sid_bytes, SHA1).digest()[:20])
    return keys


def _masterkey_sections(value: bytes) -> list[MasterKey]:
    header = MasterKeyFile(value)
    cursor = len(header)
    lengths = {field: int(header[field]) for field in ("MasterKeyLen", "BackupKeyLen", "CredHistLen", "DomainKeyLen")}
    if any(length < 0 or length > 16 * 1024 * 1024 for length in lengths.values()):
        raise ValueError("DPAPI master-key file declares an oversized section")
    if cursor + sum(lengths.values()) != len(value):
        raise ValueError("DPAPI master-key file section lengths do not cover the exact input")
    sections: list[MasterKey] = []
    for field in ("MasterKeyLen", "BackupKeyLen"):
        length = lengths[field]
        if length > 0:
            if cursor + length > len(value):
                raise ValueError("truncated DPAPI master-key file")
            sections.append(MasterKey(value[cursor : cursor + length]))
            cursor += length
    if not sections:
        raise ValueError("DPAPI master-key file has no primary or backup key section")
    return sections


def _complete_dpapi_blob(value: bytes) -> bool:
    magic = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")
    if len(value) < 44 or value[:len(magic)] != magic:
        return False
    cursor = 44

    def variable() -> bool:
        nonlocal cursor
        if cursor + 4 > len(value):
            return False
        length = int.from_bytes(value[cursor:cursor + 4], "little")
        cursor += 4
        if length > 16 * 1024 * 1024 or cursor + length > len(value):
            return False
        cursor += length
        return True

    if not variable() or cursor + 8 > len(value):
        return False
    cursor += 8
    if not variable() or not variable() or cursor + 8 > len(value):
        return False
    cursor += 8
    return variable() and variable() and variable() and cursor >= 100 and cursor == len(value)


def decrypt_masterkey(arguments: argparse.Namespace) -> dict[str, object]:
    sections = _masterkey_sections(_read_bounded(arguments.masterkey_file, 16 * 1024 * 1024, "master-key file"))
    if arguments.password_file is not None:
        if arguments.sid is None:
            raise ValueError("--sid is required with --password-file")
        candidates = _user_keys_from_password(arguments.sid, _password(arguments.password_file))
    elif arguments.user_hash_file is not None:
        if arguments.sid is None:
            raise ValueError("--sid is required with --user-hash-file")
        candidates = _user_keys_from_hash(arguments.sid, _hex_key(arguments.user_hash_file))
    elif arguments.system_key_file is not None:
        candidates = [_read_bounded(arguments.system_key_file, 1024 * 1024, "system-key file")]
    else:
        raise ValueError("one protected input file is required")

    for section_index, section in enumerate(sections):
        for candidate in candidates:
            try:
                cleartext = section.decrypt(candidate)
            except Exception:
                cleartext = None
            if cleartext is not None:
                _private_no_clobber_write(arguments.output, cleartext)
                return {"ok": True, "operation": "masterkey", "bytes": len(cleartext), "section": section_index}
    raise ValueError("none of the supplied local key derivations authenticated the master key")


def unprotect(arguments: argparse.Namespace) -> dict[str, object]:
    master_key = _read_bounded(arguments.master_key_file, 1024 * 1024, "decrypted master-key file")
    entropy = None if arguments.entropy_file is None else _read_bounded(arguments.entropy_file, 16 * 1024 * 1024, "entropy file")
    blob = _read_bounded(arguments.blob, 16 * 1024 * 1024, "DPAPI blob")
    if not _complete_dpapi_blob(blob):
        raise ValueError("DPAPI blob is not one complete length-delimited structure")
    cleartext = DPAPI_BLOB(blob).decrypt(master_key, entropy)
    if cleartext is None:
        raise ValueError("DPAPI signature authentication failed")
    _private_no_clobber_write(arguments.output, cleartext)
    return {"ok": True, "operation": "unprotect", "bytes": len(cleartext)}


def parser() -> argparse.ArgumentParser:
    root = SafeArgumentParser(description="Offline, file-only Impacket DPAPI bridge")
    commands = root.add_subparsers(dest="command", required=True, parser_class=SafeArgumentParser)

    masterkey = commands.add_parser("masterkey", help="decrypt a recovered DPAPI master-key file")
    masterkey.add_argument("--masterkey-file", type=pathlib.Path, required=True)
    masterkey.add_argument("--sid")
    inputs = masterkey.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--password-file", type=pathlib.Path)
    inputs.add_argument("--user-hash-file", type=pathlib.Path)
    inputs.add_argument("--system-key-file", type=pathlib.Path)
    masterkey.add_argument("--output", type=pathlib.Path, required=True)
    masterkey.set_defaults(handler=decrypt_masterkey)

    blob = commands.add_parser("unprotect", help="decrypt a recovered DPAPI blob using a raw decrypted master key")
    blob.add_argument("--blob", type=pathlib.Path, required=True)
    blob.add_argument("--master-key-file", type=pathlib.Path, required=True)
    blob.add_argument("--entropy-file", type=pathlib.Path)
    blob.add_argument("--output", type=pathlib.Path, required=True)
    blob.set_defaults(handler=unprotect)
    return root


def main() -> int:
    try:
        arguments = parser().parse_args()
        result = arguments.handler(arguments)
    except Exception as error:
        sensitive_debug = os.environ.get("AARK_SENSITIVE_DEBUG") == "1" or os.environ.get("AGETNIC_SENSITIVE_DEBUG") == "1"
        detail = str(error) if sensitive_debug else "operation failed; verify local inputs and enable AARK_SENSITIVE_DEBUG=1 for details"
        print(json.dumps({"ok": False, "error": detail}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
