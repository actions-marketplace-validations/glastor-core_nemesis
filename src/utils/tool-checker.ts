import { runCommand } from "./exec.ts";

export interface ToolStatus {
  name: string;
  available: boolean;
  version?: string;
  useDocker?: boolean;
}

export async function checkTool(name: string, versionFlag = "--version"): Promise<ToolStatus> {
  const result = await runCommand(name, [versionFlag], { timeoutMs: 10_000 });
  if (result.code === 0) {
    const firstLine = (result.stdout || result.stderr).trim().split("\n")[0];
    return {
      name,
      available: true,
      version: firstLine,
      useDocker: false,
    };
  }

  // Check if Docker is available as fallback
  const dockerCheck = await runCommand("docker", ["--version"], { timeoutMs: 5_000 });
  if (dockerCheck.code === 0) {
    return {
      name,
      available: true,
      version: "docker-fallback",
      useDocker: true,
    };
  }

  return {
    name,
    available: false,
  };
}
