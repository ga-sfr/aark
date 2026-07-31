import path from "node:path";
import type { RecoveryConfig, RecoveryPlan, RecoveryStep } from "./types.js";

function offsetArgs(offset: number): string[] {
  return offset === 0 ? [] : ["-o", String(offset)];
}

function step(value: Omit<RecoveryStep, "sourceMutationExpected">): RecoveryStep {
  return { ...value, sourceMutationExpected: false };
}

export function buildRecoveryPlan(config: RecoveryConfig): RecoveryPlan {
  const root = path.resolve(config.destination);
  const steps: RecoveryStep[] = [];
  if (config.image.enabled) {
    steps.push(step({
      id: "image-fast-pass",
      title: "Create or resume a low-stress evidence image",
      executable: "ddrescue",
      args: ["--no-scrape", config.source, config.image.path, config.image.mapfile],
      createsDirectories: [path.dirname(config.image.path), path.dirname(config.image.mapfile)],
      outputs: [config.image.path, config.image.mapfile],
      provenance: "allocated-reference",
      destinationWritesExpected: true,
      optional: false,
      notes: ["The mapfile makes the operation resumable.", "The source argument is never opened for writing by ddrescue."],
    }));
    steps.push(step({
      id: "image-retry-pass",
      title: "Retry unreadable areas using direct I/O",
      executable: "ddrescue",
      args: ["--direct", `--retry-passes=${config.image.retryPasses}`, config.source, config.image.path, config.image.mapfile],
      createsDirectories: [],
      outputs: [config.image.path, config.image.mapfile],
      provenance: "allocated-reference",
      destinationWritesExpected: true,
      optional: true,
      notes: ["Skip this stage for a healthy source when the first pass reports no read errors."],
    }));
  }
  const analysisSource = config.analysisSource ?? (config.image.enabled ? config.image.path : config.source);
  if (config.stages.deletedMetadata) {
    steps.push(step({
      id: "deleted-metadata-index",
      title: "Index deleted filesystem entries",
      executable: "fls",
      args: ["-r", "-d", "-p", ...offsetArgs(config.sectorOffset), analysisSource],
      stdoutFile: path.join(root, "recovery", "deleted-metadata", "fls-deleted-sensitive.txt"),
      createsDirectories: [path.join(root, "recovery", "deleted-metadata")],
      outputs: [path.join(root, "recovery", "deleted-metadata", "fls-deleted-sensitive.txt")],
      provenance: "deleted-metadata",
      destinationWritesExpected: true,
      optional: false,
      notes: ["Paths and inode metadata in this output are sensitive."],
    }));
    steps.push(step({
      id: "deleted-metadata-recover",
      title: "Recover files referenced by unallocated metadata",
      executable: "tsk_recover",
      args: [...offsetArgs(config.sectorOffset), analysisSource, path.join(root, "recovery", "metadata-deleted")],
      createsDirectories: [path.join(root, "recovery", "metadata-deleted")],
      outputs: [path.join(root, "recovery", "metadata-deleted")],
      provenance: "deleted-metadata",
      destinationWritesExpected: true,
      optional: false,
      notes: ["tsk_recover defaults to unallocated files only; do not add -e unless allocated files are intentionally desired."],
    }));
  }
  if (config.stages.ntfsUndelete) {
    steps.push(step({
      id: "ntfs-undelete-scan",
      title: "Scan NTFS deleted records",
      executable: "ntfsundelete",
      args: ["--scan", "--parent", analysisSource],
      stdoutFile: path.join(root, "recovery", "ntfsundelete", "scan-sensitive.txt"),
      createsDirectories: [path.join(root, "recovery", "ntfsundelete")],
      outputs: [path.join(root, "recovery", "ntfsundelete", "scan-sensitive.txt")],
      provenance: "deleted-metadata",
      destinationWritesExpected: true,
      optional: true,
      notes: ["Use a partition or decrypted NTFS volume as analysisSource; ntfsundelete does not accept a partition offset."],
    }));
    steps.push(step({
      id: "ntfs-undelete-recover",
      title: "Recover every NTFS deleted record with recoverable data",
      executable: "ntfsundelete",
      args: ["--undelete", "--percentage", "0", "--match", "*", "--destination", path.join(root, "recovery", "ntfsundelete", "files"), analysisSource],
      createsDirectories: [path.join(root, "recovery", "ntfsundelete", "files")],
      outputs: [path.join(root, "recovery", "ntfsundelete", "files")],
      provenance: "deleted-metadata",
      destinationWritesExpected: true,
      optional: true,
      notes: ["The optimistic overwrite-cluster option is intentionally not enabled."],
    }));
  }
  if (config.stages.unallocatedStream) {
    steps.push(step({
      id: "unallocated-stream",
      title: "Extract filesystem-unallocated data units",
      executable: "blkls",
      args: ["-A", ...offsetArgs(config.sectorOffset), analysisSource],
      stdoutFile: path.join(root, "recovery", "unallocated", "free-space.raw"),
      createsDirectories: [path.join(root, "recovery", "unallocated")],
      outputs: [path.join(root, "recovery", "unallocated", "free-space.raw")],
      provenance: "unallocated-stream",
      destinationWritesExpected: true,
      optional: false,
      notes: ["The output can approach the size of all free space and may contain highly sensitive fragments."],
    }));
  }
  if (config.stages.signatureCarving) {
    const unallocatedInput = path.join(root, "recovery", "unallocated", "free-space.raw");
    const carveRoot = path.join(root, "recovery", "carved");
    steps.push(step({
      id: "signature-carving",
      title: "Carve known file formats from the extracted unallocated stream",
      executable: "photorec",
      args: [
        "/d", path.join(carveRoot, "recup"),
        "/cmd", unallocatedInput, config.photoRecCommand,
      ],
      createsDirectories: [carveRoot],
      outputs: [carveRoot],
      provenance: "unallocated-carve",
      destinationWritesExpected: true,
      optional: true,
      notes: ["The input was produced by blkls from filesystem-unallocated units; PhotoRec never receives the allocated source.", "PhotoRec output has reconstructed names and needs strict downstream validation."],
    }));
  }
  if (config.stages.volumeShadows) {
    steps.push(step({
      id: "volume-shadow-inventory",
      title: "Inventory Windows Volume Shadow Copies",
      executable: "vshadowinfo",
      args: [analysisSource],
      stdoutFile: path.join(root, "recovery", "volume-shadows", "vshadowinfo-sensitive.txt"),
      createsDirectories: [path.join(root, "recovery", "volume-shadows")],
      outputs: [path.join(root, "recovery", "volume-shadows", "vshadowinfo-sensitive.txt")],
      provenance: "shadow-copy",
      destinationWritesExpected: true,
      optional: true,
      notes: ["Mount and compare discovered snapshots read-only in a separate reviewed step."],
    }));
  }
  if (config.stages.residualMemory) {
    if (config.mountedReadOnlyRoot === undefined) {
      throw new Error("residualMemory requires mountedReadOnlyRoot in the configuration");
    }
    for (const filename of ["hiberfil.sys", "pagefile.sys", "swapfile.sys"]) {
      steps.push(step({
        id: `residual-memory-${filename.replace(/\W/g, "-")}`,
        title: `Scan ${filename} with bulk_extractor`,
        executable: "bulk_extractor",
        args: ["-x", "all", "-e", "aes", "-e", "base64", "-e", "find", "-e", "hiberfile", "-o", path.join(root, "recovery", "residual-memory", filename), path.join(config.mountedReadOnlyRoot, filename)],
        createsDirectories: [path.join(root, "recovery", "residual-memory")],
        outputs: [path.join(root, "recovery", "residual-memory", filename)],
        provenance: "residual-memory",
        destinationWritesExpected: true,
        optional: true,
        notes: ["Residual memory may be stale, but filesystem deletion cannot be proven from a memory hit alone."],
      }));
    }
  }
  if (config.stages.deletedRegistryCells) {
    if (config.mountedReadOnlyRoot === undefined) {
      throw new Error("deletedRegistryCells requires mountedReadOnlyRoot in the configuration");
    }
    const hive = path.join(config.mountedReadOnlyRoot, "Windows", "System32", "config", "SOFTWARE");
    steps.push(step({
      id: "deleted-registry-cells",
      title: "Recover deleted and unallocated SOFTWARE hive cells",
      executable: "reglookup-recover",
      args: ["-r", "-l", hive],
      stdoutFile: path.join(root, "recovery", "registry", "software-free-cells-sensitive.csv"),
      createsDirectories: [path.join(root, "recovery", "registry")],
      outputs: [path.join(root, "recovery", "registry", "software-free-cells-sensitive.csv")],
      provenance: "deleted-metadata",
      destinationWritesExpected: true,
      optional: true,
      notes: ["The raw CSV may contain credentials and identities; it is intentionally marked sensitive."],
    }));
  }
  return {
    version: 1,
    caseId: config.caseId,
    source: config.source,
    analysisSource,
    destination: root,
    steps,
    warnings: [
      "Never write recovery output to the source device.",
      "TRIM, overwrite, fragmentation, and metadata reuse can make deleted data unrecoverable.",
      "Carved and residual-memory artifacts need validation and do not prove an original deleted pathname.",
    ],
  };
}
