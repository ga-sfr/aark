import { spawnSync } from "node:child_process";

const candidates = process.platform === "win32"
  ? [["py", "-3"], ["python"], ["python3"]]
  : [["python3"], ["python"]];
const code = "import ast,pathlib; ast.parse(pathlib.Path('optional/impacket/dpapi_bridge.py').read_text(encoding='utf-8'))";
let found = false;
for (const [command, ...prefix] of candidates) {
  const probe = spawnSync(command, [...prefix, "--version"], { shell: false, windowsHide: true, encoding: "utf8" });
  if (probe.status !== 0 || !/^Python 3\./.test(probe.stdout || probe.stderr || "")) continue;
  found = true;
  const result = spawnSync(command, [...prefix, "-c", code], { shell: false, windowsHide: true, stdio: "inherit" });
  process.exitCode = result.status ?? 1;
  break;
}
if (!found) {
  process.stderr.write("Python 3 is required for check:python (py -3, python3, or python).\n");
  process.exitCode = 1;
}
