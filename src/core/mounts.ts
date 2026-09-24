import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { captureCommand, WINDOWS_MOUNTVOL } from "./command.js";

export interface MountRecord {
  source: string;
  target: string;
  filesystem: string;
  options: string[];
}

function unescapeMount(value: string): string {
  return value.replace(/\\040/g, " ").replace(/\\011/g, "\t").replace(/\\012/g, "\n").replace(/\\134/g, "\\");
}

export function windowsMountvolToMounts(value: string): MountRecord[] {
  const records: MountRecord[] = [];
  let volume: string | undefined;
  for (const rawLine of value.split(/\r?\n/)) {
    const line = rawLine.trim();
    const volumeMatch = /^\\\\\?\\Volume\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}\\$/.exec(line);
    if (volumeMatch?.[1] !== undefined) {
      volume = volumeMatch[1].toUpperCase();
      continue;
    }
    if (volume === undefined || line === "") continue;
    if (!/^[A-Za-z]:\\(?:[^<>:"/\\|?*\x00-\x1F]+\\)*$/.test(line)) {
      // This also handles the localized form of "NO MOUNT POINTS" without
      // depending on display language or accepting a later unrelated line.
      volume = undefined;
      continue;
    }
    records.push({
      source: `windows-volume:${volume}`,
      target: `${line[0]?.toUpperCase()}${line.slice(1)}`,
      filesystem: "unknown",
      options: ["rw", "windows-local"],
    });
  }
  return records;
}

async function windowsMounts(): Promise<MountRecord[]> {
  const result = await captureCommand(WINDOWS_MOUNTVOL, [], {
    maxCaptureBytes: 256 * 1024,
    timeoutMs: 10_000,
  });
  if (result.exitCode !== 0 || result.terminationReason !== null || result.stdoutTruncated || result.stderrTruncated) {
    throw new Error("could not inventory Windows local volume mount points safely");
  }
  const records = windowsMountvolToMounts(result.stdout.toString("utf8"));
  if (records.length === 0) throw new Error("Windows volume inventory returned no usable local mount points");
  for (const record of records) {
    try {
      // mountvol lists volume-manager mount points and omits mapped network
      // drives. libuv's exact st_dev identity binds each reachable path to the
      // local volume that actually backs it without WMI or DriveInfo queries.
      const serial = (await stat(record.target, { bigint: true })).dev.toString(16).toUpperCase().padStart(8, "0");
      record.source = `${record.source}:${serial}`;
    } catch {
      // An inaccessible local drive cannot safely back a protected path. Leave
      // it marked so protected-path checks fail closed if it is selected.
      record.options.push("windows-inaccessible");
    }
  }
  return records;
}

export async function mounts(): Promise<MountRecord[]> {
  if (process.platform === "win32") return await windowsMounts();
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
    const target = path.resolve(record.target);
    const relative = path.relative(target, resolved);
    if (relative !== "" && (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative))) continue;
    // /proc/self/mounts is ordered by mount creation. For stacked mounts with
    // the same target, the later record is the visible topmost mount.
    if (selected === undefined || target.length >= path.resolve(selected.target).length) selected = record;
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
  if (record.options.includes("windows-network")) return true;
  const filesystem = record.filesystem.toLowerCase();
  const known = new Set(["9p", "afs", "ceph", "cifs", "davfs", "glusterfs", "lustre", "nfs", "nfs4", "smb3", "virtiofs"]);
  const knownLocalFuse = new Set([
    "fuse.dislocker",
    "fuse.exfat",
    "fuse.ntfs",
    "fuse.ntfs-3g",
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
  if (record.options.includes("windows-inaccessible")) throw new Error("protected Windows volume identity could not be read safely");
  if (filesystemIsNetwork(record)) return true;
  if (record.options.includes("windows-local") && record.source.startsWith("windows-volume:")) return false;
  if (!record.source.startsWith("/dev/")) return false;
  const source = record.source.replace(/\[[^\]]*\]$/, "");
  const result = await captureCommand("lsblk", ["--inverse", "--json", "--paths", "--output", "PATH,TYPE,TRAN,SUBSYSTEMS", source], {
    maxCaptureBytes: 64 * 1024,
    timeoutMs: 30_000,
  });
  if (result.exitCode !== 0) throw new Error("could not resolve the physical transport backing a protected mount");
  if (result.stdoutTruncated) throw new Error("lsblk output exceeded its bounded safety limit while resolving a protected mount");
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
