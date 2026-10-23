export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
  success: boolean;
}

export async function runCommand(
  cmd: string,
  args: string[],
  options?: {
    cwd?: string;
    env?: Record<string, string>;
    timeoutMs?: number;
  },
): Promise<ExecResult> {
  const timeoutMs = options?.timeoutMs ?? 300_000; // 5 min default

  const abortController = new AbortController();
  const timer = setTimeout(() => abortController.abort(), timeoutMs);

  const command = new Deno.Command(cmd, {
    args,
    cwd: options?.cwd,
    env: options?.env,
    stdout: "piped",
    stderr: "piped",
    signal: abortController.signal,
  });

  try {
    const child = command.spawn();

    const output = await child.output();
    clearTimeout(timer);

    const decoder = new TextDecoder();
    return {
      code: output.code,
      stdout: decoder.decode(output.stdout),
      stderr: decoder.decode(output.stderr),
      success: output.code === 0,
    };
  } catch (error) {
    clearTimeout(timer);
    if (error instanceof Deno.errors.NotFound) {
      return {
        code: 127,
        stdout: "",
        stderr: `Command "${cmd}" not found in PATH`,
        success: false,
      };
    }
    throw error;
  }
}
