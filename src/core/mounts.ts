import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { captureCommand, WINDOWS_POWERSHELL } from "./command.js";

export interface MountRecord {
  source: string;
  target: string;
  filesystem: string;
  options: string[];
}

interface WindowsLogicalDisk {
  DeviceID?: unknown;
  DriveType?: unknown;
  FileSystem?: unknown;
  VolumeSerialNumber?: unknown;
}

const WINDOWS_LOGICAL_DISK_QUERY = [
  "$mutex = [System.Threading.Mutex]::new($false, 'Local\\AARK-Windows-Volume-Inventory-v1');",
  "$acquired = $false;",
  "try {",
  "try { $acquired = $mutex.WaitOne(20000) } catch [System.Threading.AbandonedMutexException] { $acquired = $true };",
  "if (-not $acquired) { throw 'timed out waiting for bounded Windows volume inventory serialization' };",
  "@(",
  "[System.IO.DriveInfo]::GetDrives() | ForEach-Object {",
  "$filesystem = 'unknown';",
  "if ([int]$_.DriveType -ne 4 -and $_.IsReady) { try { $filesystem = $_.DriveFormat } catch {} };",
  "[pscustomobject]@{ DeviceID = $_.Name.Substring(0, 2); DriveType = [int]$_.DriveType; FileSystem = $filesystem }",
  "}",
  ") | ConvertTo-Json -Compress",
  "} finally { if ($acquired) { $mutex.ReleaseMutex() }; $mutex.Dispose() }",
].join(" ");

function unescapeMount(value: string): string {
  return value.replace(/\\040/g, " ").replace(/\\011/g, "\t").replace(/\\012/g, "\n").replace(/\\134/g, "\\");
}

function validWindowsLogicalDisk(value: unknown): value is WindowsLogicalDisk {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function windowsLogicalDisksToMounts(value: unknown): MountRecord[] {
  const entries = Array.isArray(value) ? value : [value];
  const records: MountRecord[] = [];
  for (const entry of entries) {
    if (!validWindowsLogicalDisk(entry)) continue;
    const device = typeof entry.DeviceID === "string" ? entry.DeviceID.toUpperCase() : "";
    const driveType = typeof entry.DriveType === "number" ? entry.DriveType : Number.NaN;
    const filesystem = typeof entry.FileSystem === "string" && entry.FileSystem !== "" ? entry.FileSystem : "unknown";
    const serial = typeof entry.VolumeSerialNumber === "string" && /^[A-Fa-f0-9]+$/.test(entry.VolumeSerialNumber)
      ? entry.VolumeSerialNumber.toUpperCase()
      : "unknown";
    if (!/^[A-Z]:$/.test(device) || !Number.isInteger(driveType)) continue;
    const network = driveType === 4 || !new Set([2, 3, 5, 6]).has(driveType);
    records.push({
      source: `windows-volume:${device}:${serial}`,
      target: `${device}\\`,
      filesystem,
      options: ["rw", network ? "windows-network" : "windows-local", `drive-type=${driveType}`],
    });
  }
  return records;
}

async function windowsMounts(): Promise<MountRecord[]> {
  const result = await captureCommand(WINDOWS_POWERSHELL, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    WINDOWS_LOGICAL_DISK_QUERY,
  ], {
    maxCaptureBytes: 256 * 1024,
    timeoutMs: 30_000,
  });
  if (result.exitCode !== 0 || result.stdoutTruncated) {
    throw new Error("could not inventory Windows logical volumes safely");
  }
  let document: unknown;
  try {
    document = JSON.parse(result.stdout.toString("utf8").replace(/^\uFEFF/, ""));
  } catch (error) {
    throw new Error("Windows logical-volume inventory returned invalid JSON", { cause: error });
  }
  const records = windowsLogicalDisksToMounts(document);
  for (const record of records) {
    if (!record.options.includes("windows-local")) continue;
    try {
      // libuv exposes the Windows volume serial number as st_dev. This avoids
      // WMI/CIM, which can hang under concurrent scanners and hosted runners.
      const serial = (await stat(record.target, { bigint: true })).dev.toString(16).toUpperCase().padStart(8, "0");
      record.source = `windows-volume:${record.target.slice(0, 2)}:${serial}`;
    } catch {
      // An inaccessible local drive cannot safely back a protected path. Leave
      // it marked so protected-path checks fail closed if it is selected.
      record.options.push("windows-inaccessible");
    }
  }
  if (records.length === 0) throw new Error("Windows logical-volume inventory returned no usable local roots");
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
