import { captureCommand } from "../core/command.js";

export async function machineInventory(): Promise<unknown> {
  const [block, mounts] = await Promise.all([
    captureCommand("lsblk", [
      "--json",
      "--bytes",
      "--output",
      "NAME,PATH,TYPE,RO,SIZE,FSTYPE,FSVER,LABEL,UUID,MODEL,SERIAL,MOUNTPOINTS,PKNAME",
    ], { timeoutMs: 30_000 }),
    captureCommand("findmnt", ["--json", "--bytes", "--output", "SOURCE,TARGET,FSTYPE,OPTIONS,SIZE,AVAIL"], { timeoutMs: 30_000 }),
  ]);
  if (block.exitCode !== 0 || mounts.exitCode !== 0) throw new Error("failed to inventory block devices or mounts");
  if (block.stdoutTruncated || mounts.stdoutTruncated) throw new Error("device inventory exceeded the bounded command-output capture");
  let blockDevices: unknown;
  let mountedFilesystems: unknown;
  try {
    blockDevices = JSON.parse(block.stdout.toString("utf8"));
    mountedFilesystems = JSON.parse(mounts.stdout.toString("utf8"));
  } catch (error) {
    throw new Error("device inventory tools returned invalid JSON", { cause: error });
  }
  return {
    generatedAt: new Date().toISOString(),
    blockDevices,
    mounts: mountedFilesystems,
  };
}
