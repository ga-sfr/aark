import { readFile } from "node:fs/promises";
import path from "node:path";
import { captureCommand } from "./command.js";

export interface MountRecord {
  source: string;
  target: string;
  filesystem: string;
  options: string[];
}

function unescapeMount(value: string): string {
  return value.replace(/\\040/g, " ").replace(/\\011/g, "\t").replace(/\\012/g, "\n").replace(/\\134/g, "\\");
}

export async function mounts(): Promise<MountRecord[]> {
  const records: MountRecord[] = [];
  for (const line of (await readFile("/proc/self/mounts", "utf8")).split("\n")) {
    const fields = line.split(" ");
    if (fields.length < 4) continue;
    records.push({
      source: unescapeMount(fields[0] ?? ""),
      target: unescapeMount(fields[1] ?? ""),
      filesystem: fields[2] ?? "unknown",
      options: (fields[3] ?? "").split(","),
    });
  }
  return records;
}

export function mountForPathFrom(records: MountRecord[], input: string): MountRecord | undefined {
  const resolved = path.resolve(input);
  let selected: MountRecord | undefined;
  for (const record of records) {
    if (resolved !== record.target && !resolved.startsWith(`${record.target.replace(/\/$/, "")}/`)) continue;
    // /proc/self/mounts is ordered by mount creation. For stacked mounts with
    // the same target, the later record is the visible topmost mount.
    if (selected === undefined || record.target.length >= selected.target.length) selected = record;
  }
  return selected;
}

export async function mountForPath(input: string): Promise<MountRecord | undefined> {
  return mountForPathFrom(await mounts(), input);
}

export function mountIsReadOnly(record: MountRecord | undefined): boolean {
  return record !== undefined && record.options.includes("ro") && !record.options.includes("rw");
}

export function filesystemIsNetwork(record: MountRecord | undefined): boolean {
  if (record === undefined) return false;
  const filesystem = record.filesystem.toLowerCase();
  const known = new Set(["9p", "afs", "ceph", "cifs", "davfs", "glusterfs", "lustre", "nfs", "nfs4", "smb3", "virtiofs"]);
  const knownLocalFuse = new Set([
    "fuse.bindfs",
    "fuse.dislocker",
    "fuse.encfs",
    "fuse.exfat",
    "fuse.mergerfs",
    "fuse.ntfs",
    "fuse.ntfs-3g",
    "fuse.unionfs",
    "fuseblk",
  ]);
  return known.has(filesystem)
    || (filesystem === "fuse" || filesystem.startsWith("fuse.")) && !knownLocalFuse.has(filesystem)
    || record.source.startsWith("//")
    || /^\/dev\/(?:nbd|rbd|drbd)/.test(record.source);
}

interface LsblkTransportNode {
  path?: string;
  type?: string;
  tran?: string | null;
  subsystems?: string | null;
  children?: LsblkTransportNode[];
}

function flattenBlockDevices(nodes: LsblkTransportNode[]): LsblkTransportNode[] {
  return nodes.flatMap((node) => [node, ...flattenBlockDevices(node.children ?? [])]);
}

export function blockTransportIsNetwork(device: string, transport?: string | null, subsystems?: string | null): boolean {
  const normalized = transport?.toLowerCase();
  const subsystemNames = new Set((subsystems ?? "").toLowerCase().split(":").filter(Boolean));
  return normalized === "iscsi"
    || normalized === "fcoe"
    || normalized === "aoe"
    || normalized === "tcp"
    || normalized === "rdma"
    || ["iscsi", "fcoe", "aoe", "nvme-fabrics", "nbd", "rbd", "drbd"].some((name) => subsystemNames.has(name))
    || /^\/dev\/(?:nbd|rbd|drbd)/.test(device);
}

export async function mountIsNetworkBacked(record: MountRecord | undefined): Promise<boolean> {
  if (record === undefined) throw new Error("could not determine the mount backing a protected path");
  if (filesystemIsNetwork(record)) return true;
  if (!record.source.startsWith("/dev/")) return false;
  const source = record.source.replace(/\[[^\]]*\]$/, "");
  const result = await captureCommand("lsblk", ["--inverse", "--json", "--paths", "--output", "PATH,TYPE,TRAN,SUBSYSTEMS", source], {
    maxCaptureBytes: 64 * 1024,
    timeoutMs: 30_000,
  });
  if (result.exitCode !== 0) throw new Error("could not resolve the physical transport backing a protected mount");
  let document: { blockdevices?: LsblkTransportNode[] };
  try {
    document = JSON.parse(result.stdout.toString("utf8")) as { blockdevices?: LsblkTransportNode[] };
  } catch (error) {
    throw new Error("lsblk returned invalid JSON while resolving a protected mount", { cause: error });
  }
  const disks = flattenBlockDevices(document.blockdevices ?? []).filter((node) => node.type === "disk" && node.path?.startsWith("/dev/") === true);
  if (disks.length === 0) throw new Error("could not identify the physical device backing a protected mount");
  return disks.some((node) => blockTransportIsNetwork(node.path ?? "", node.tran, node.subsystems));
}

export function filesystemEnforcesUnixModes(record: MountRecord | undefined): boolean {
  if (record === undefined) return false;
  return new Set([
    "btrfs",
    "ext2",
    "ext3",
    "ext4",
    "f2fs",
    "jfs",
    "nilfs2",
    "reiserfs",
    "tmpfs",
    "ubifs",
    "xfs",
    "zfs",
  ]).has(record.filesystem.toLowerCase());
}
