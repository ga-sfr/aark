import assert from "node:assert/strict";
import test from "node:test";
import { blockTransportIsNetwork, filesystemEnforcesUnixModes, filesystemIsNetwork, mountForPath, mountForPathFrom, mountIsNetworkBacked, mountIsReadOnly, windowsLogicalDisksToMounts, type MountRecord } from "../core/mounts.js";

function mount(filesystem: string, source = "/dev/test", options = ["rw"]): MountRecord {
  return { source, target: "/mnt/test", filesystem, options };
}

test("mount classification is conservative for permissions, read-only state, and network boundaries", () => {
  assert.equal(filesystemEnforcesUnixModes(mount("ext4")), true);
  assert.equal(filesystemEnforcesUnixModes(mount("ntfs3")), false);
  assert.equal(filesystemEnforcesUnixModes(undefined), false);
  assert.equal(mountIsReadOnly(mount("ext4", "/dev/test", ["ro"])), true);
  assert.equal(mountIsReadOnly(mount("ext4", "/dev/test", ["ro", "rw"])), false);
  assert.equal(filesystemIsNetwork(mount("nfs4", "server:/case")), true);
  assert.equal(filesystemIsNetwork(mount("fuse.s3fs", "bucket")), true);
  assert.equal(filesystemIsNetwork(mount("fuse", "opaque")), true);
  assert.equal(filesystemIsNetwork(mount("fuse.unknown-provider", "opaque")), true);
  assert.equal(filesystemIsNetwork(mount("fuse.bindfs", "/network-or-local-layer")), true);
  assert.equal(filesystemIsNetwork(mount("fuse.mergerfs", "/possibly-mixed-layers")), true);
  assert.equal(filesystemIsNetwork(mount("fuse.encfs", "/unknown-backing-layer")), true);
  assert.equal(filesystemIsNetwork(mount("fuse.ntfs-3g", "/dev/test")), false);
  assert.equal(filesystemIsNetwork(mount("fuse.dislocker", "/case/dislocker-file")), false);
  assert.equal(filesystemIsNetwork(mount("cifs", "//server/share")), true);
  assert.equal(filesystemIsNetwork(mount("ext4", "/dev/nbd0p1")), true);
  assert.equal(filesystemIsNetwork(mount("xfs", "/dev/rbd0")), true);
  assert.equal(filesystemIsNetwork(mount("tmpfs", "tmpfs")), false);
  assert.equal(blockTransportIsNetwork("/dev/sda", "iscsi"), true);
  assert.equal(blockTransportIsNetwork("/dev/nvme0n1", "tcp"), true);
  assert.equal(blockTransportIsNetwork("/dev/nvme0n1", "nvme", "block:nvme:nvme-fabrics"), true);
  assert.equal(blockTransportIsNetwork("/dev/nbd0", null), true);
  assert.equal(blockTransportIsNetwork("/dev/rbd0", null), true);
  assert.equal(blockTransportIsNetwork("/dev/drbd0", null), true);
  assert.equal(blockTransportIsNetwork("/dev/sda", "usb"), false);
  assert.equal(mountForPathFrom([
    { source: "/dev/root", target: "/", filesystem: "ext4", options: ["rw"] },
    { source: "server:/case", target: "/mnt/recovered/remote", filesystem: "nfs4", options: ["ro"] },
  ], "/mnt/recovered/remote/user/file")?.filesystem, "nfs4");
  assert.equal(mountForPathFrom([
    { source: "/dev/local", target: "/mnt/test", filesystem: "ext4", options: ["rw"] },
    { source: "server:/replacement", target: "/mnt/test", filesystem: "nfs4", options: ["ro"] },
  ], "/mnt/test/file")?.filesystem, "nfs4");
});

test("Windows logical disks retain volume identity and reject mapped drives", async () => {
  const records = windowsLogicalDisksToMounts([
    { DeviceID: "F:", DriveType: 3, FileSystem: "exFAT", VolumeSerialNumber: "012ACA6C" },
    { DeviceID: "Z:", DriveType: 4, FileSystem: "NTFS", VolumeSerialNumber: "DEADBEEF" },
  ]);
  assert.equal(records.length, 2);
  assert.equal(records[0]?.source, "windows-volume:F::012ACA6C");
  assert.equal(records[0]?.target, "F:\\");
  assert.equal(records[0]?.filesystem, "exFAT");
  assert.equal(filesystemIsNetwork(records[0]), false);
  assert.equal(await mountIsNetworkBacked(records[0]), false);
  assert.equal(filesystemIsNetwork(records[1]), true);
  assert.equal(await mountIsNetworkBacked(records[1]), true);
  if (process.platform === "win32") {
    assert.equal(mountForPathFrom(records, "F:\\recovery\\case")?.source, "windows-volume:F::012ACA6C");
  }
});

test("Windows live volume inventory obtains an exact local volume identity without WMI", { skip: process.platform !== "win32" }, async () => {
  const record = await mountForPath(process.cwd());
  assert.ok(record?.source.startsWith(`windows-volume:${process.cwd().slice(0, 2).toUpperCase()}:`));
  assert.equal(record?.source.endsWith(":unknown"), false);
  assert.equal(record?.options.includes("windows-inaccessible"), false);
  assert.equal(await mountIsNetworkBacked(record), false);
});
