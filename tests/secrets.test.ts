import { assertEquals } from "@std/assert";
import { join } from "@std/path";
import { GitleaksScanner } from "../src/scanners/gitleaks.ts";
import { loadConfig } from "../src/config.ts";

Deno.test("GitleaksScanner native fallback detects leaked API tokens", async () => {
  const tempDir = await Deno.makeTempDir({ prefix: "nemesis_secret_test_" });

  try {
    // Write sample files with fake secrets
    await Deno.writeTextFile(
      join(tempDir, "client.ts"),
      `
      // Fake GitHub Token for testing
      const token = "ghp_123456789012345678901234567890123456";
      // Fake AWS Key
      const awsKey = "AKIAIOSFODNN7EXAMPLE";
      console.log(token, awsKey);
      `,
    );

    const config = loadConfig([
      "--path",
      tempDir,
      "--output-dir",
      join(tempDir, ".reports"),
      "--secrets",
    ]);

    const scanner = new GitleaksScanner();
    const result = await scanner.run(config);

    assertEquals(result.summary.status, "success");
    assertEquals(result.findings.length >= 2, true);

    const ghFinding = result.findings.find((f) => f.ruleId === "github-pat");
    assertEquals(ghFinding !== undefined, true);
    assertEquals(ghFinding?.severity, "CRITICAL");

    const awsFinding = result.findings.find((f) =>
      f.ruleId === "aws-access-key"
    );
    assertEquals(awsFinding !== undefined, true);
    assertEquals(awsFinding?.severity, "CRITICAL");
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});
