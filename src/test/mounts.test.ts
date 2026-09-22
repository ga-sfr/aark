import assert from "node:assert/strict";
import test from "node:test";
import { blockTransportIsNetwork, filesystemEnforcesUnixModes, filesystemIsNetwork, mountForPath, mountForPathFrom, mountIsNetworkBacked, mountIsReadOnly, mounts, windowsMountvolToMounts, type MountRecord } from "../core/mounts.js";

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

test("Windows mountvol output retains only local volume-manager mount points", async () => {
  const records = windowsMountvolToMounts([
    "Possible values for VolumeName along with current mount points are:",
    "",
    "    \\\\?\\Volume{012aca6c-1111-2222-3333-444444444444}\\",
    "        F:\\",
    "        F:\\mounted volume\\",
    "",
    "    \\\\?\\Volume{deadbeef-1111-2222-3333-444444444444}\\",
    "        *** AUCUN POINT DE MONTAGE ***",
    "        Z:\\not-a-real-following-mount",
  ].join("\r\n"));
  assert.equal(records.length, 2);
  assert.equal(records[0]?.source, "windows-volume:012ACA6C-1111-2222-3333-444444444444");
  assert.equal(records[0]?.target, "F:\\");
  assert.equal(records[1]?.target, "F:\\mounted volume\\");
  assert.equal(records[0]?.filesystem, "unknown");
  assert.equal(filesystemIsNetwork(records[0]), false);
  assert.equal(await mountIsNetworkBacked(records[0]), false);
});

test("Windows live volume inventory obtains an exact local volume identity without WMI", { skip: process.platform !== "win32" }, async () => {
  const record = await mountForPath(process.cwd());
  assert.match(record?.source ?? "", /^windows-volume:[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}:[0-9A-F]{8,}$/);
  assert.equal(record?.options.includes("windows-local"), true);
  assert.equal(record?.options.includes("windows-inaccessible"), false);
  assert.equal(await mountIsNetworkBacked(record), false);
});

test("concurrent Windows volume inventories complete without starving their bounded children", { skip: process.platform !== "win32" }, async () => {
  const inventories = await Promise.all(Array.from({ length: 4 }, async () => await mounts()));
  assert.equal(inventories.length, 4);
  for (const records of inventories) assert.ok(records.some((record) => record.options.includes("windows-local")));
});
