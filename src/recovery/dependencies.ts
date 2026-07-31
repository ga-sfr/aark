import { captureCommand, commandExists } from "../core/command.js";

export interface Dependency {
  executable: string;
  ubuntuPackage: string;
  layer: "core" | "recovery" | "mining";
  purpose: string;
  required: boolean;
  probeArgs?: string[];
}

export const DEPENDENCIES: Dependency[] = [
  { executable: "lsblk", ubuntuPackage: "util-linux", layer: "core", purpose: "block-device inventory and read-only checks", required: true },
  { executable: "findmnt", ubuntuPackage: "util-linux", layer: "core", purpose: "mount and destination safety checks", required: true },
  { executable: "ddrescue", ubuntuPackage: "gddrescue", layer: "recovery", purpose: "resumable evidence imaging", required: false },
  { executable: "fls", ubuntuPackage: "sleuthkit", layer: "recovery", purpose: "deleted filesystem metadata indexing", required: false },
  { executable: "mmls", ubuntuPackage: "sleuthkit", layer: "recovery", purpose: "read-only partition and sector-offset inventory", required: false },
  { executable: "tsk_recover", ubuntuPackage: "sleuthkit", layer: "recovery", purpose: "deleted-file extraction", required: false },
  { executable: "blkls", ubuntuPackage: "sleuthkit", layer: "recovery", purpose: "unallocated-space extraction", required: false },
  { executable: "ntfsundelete", ubuntuPackage: "ntfs-3g", layer: "recovery", purpose: "NTFS deleted-record recovery", required: false },
  { executable: "photorec", ubuntuPackage: "testdisk", layer: "recovery", purpose: "signature carving", required: false },
  { executable: "vshadowinfo", ubuntuPackage: "libvshadow-utils", layer: "recovery", purpose: "Volume Shadow Copy inventory", required: false },
  { executable: "vshadowmount", ubuntuPackage: "libvshadow-utils", layer: "recovery", purpose: "read-only Volume Shadow Copy access", required: false },
  { executable: "dislocker", ubuntuPackage: "dislocker", layer: "recovery", purpose: "read-only BitLocker access", required: false },
  { executable: "bulk_extractor", ubuntuPackage: "bulk-extractor or upstream build", layer: "mining", purpose: "compressed residual-memory and bulk feature scanning", required: false },
  { executable: "reglookup-recover", ubuntuPackage: "libregfi-utils", layer: "mining", purpose: "deleted Windows registry-cell recovery", required: false },
  { executable: "sqlite3", ubuntuPackage: "sqlite3", layer: "mining", purpose: "read-only validation of recovered SQLite databases", required: false },
  { executable: "python3", probeArgs: ["-c", "import impacket, Cryptodome"], ubuntuPackage: "python3-impacket", layer: "mining", purpose: "optional Impacket DPAPI bridge", required: false },
];

export async function dependencyReport(): Promise<Array<Dependency & { available: boolean }>> {
  return await Promise.all(DEPENDENCIES.map(async (dependency) => ({
    ...dependency,
    available: dependency.probeArgs === undefined
      ? await commandExists(dependency.executable)
      : await captureCommand(dependency.executable, dependency.probeArgs, { maxCaptureBytes: 4096, timeoutMs: 30_000 })
        .then((result) => result.exitCode === 0)
        .catch(() => false),
  })));
}
