import { parseArgs } from "@std/cli";
import * as core from "@actions/core";
import { NemesisConfig } from "./types.ts";

function getActionInput(name: string, defaultValue = ""): string {
  try {
    const val = core.getInput(name);
    return val !== "" ? val : defaultValue;
  } catch {
    const envKey = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
    return Deno.env.get(envKey) ?? defaultValue;
  }
}

function getActionBooleanInput(name: string, defaultValue: boolean): boolean {
  try {
    const val = core.getInput(name);
    if (val === "") return defaultValue;
    return val.toLowerCase() === "true" || val === "1";
  } catch {
    const envKey = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
    const val = Deno.env.get(envKey);
    if (!val) return defaultValue;
    return val.toLowerCase() === "true" || val === "1";
  }
}

export function loadConfig(cliArgs: string[]): NemesisConfig {
  const parsed = parseArgs(cliArgs, {
    string: [
      "path",
      "output-dir",
      "semgrep-rules",
      "trivy-severity",
      "github-token",
      "max-file-size",
    ],
    boolean: [
      "secrets",
      "sast",
      "sca",
      "hygiene",
      "require-license",
      "all",
      "fail-on-critical",
      "fail-on-high",
      "fail-on-medium",
      "post-pr-comment",
      "annotations",
      "verbose",
      "help",
    ],
    alias: {
      p: "path",
      h: "help",
      v: "verbose",
      a: "all",
    },
    default: {
      path: ".",
      "output-dir": ".nemesis-reports",
      "semgrep-rules": "p/security-audit",
      "trivy-severity": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
      "max-file-size": "10",
      verbose: false,
    },
  });

  const isGitHubActions = !!Deno.env.get("GITHUB_ACTIONS");

  const scanAll = parsed.all ?? false;
  const hasSecretsFlag = cliArgs.includes("--secrets") || cliArgs.includes("--no-secrets");
  const hasSastFlag = cliArgs.includes("--sast") || cliArgs.includes("--no-sast");
  const hasScaFlag = cliArgs.includes("--sca") || cliArgs.includes("--no-sca");
  const hasHygieneFlag = cliArgs.includes("--hygiene") || cliArgs.includes("--no-hygiene");
  const anyExplicitModule = hasSecretsFlag || hasSastFlag || hasScaFlag || hasHygieneFlag;
  const defaultScan = scanAll || !anyExplicitModule;

  const targetPath = isGitHubActions
    ? getActionInput("target-path", parsed.path)
    : parsed.path;

  const scanSecrets = isGitHubActions
    ? getActionBooleanInput("scan-secrets", true)
    : (hasSecretsFlag ? parsed.secrets : defaultScan);

  const scanSast = isGitHubActions
    ? getActionBooleanInput("scan-sast", true)
    : (hasSastFlag ? parsed.sast : defaultScan);

  const scanSca = isGitHubActions
    ? getActionBooleanInput("scan-sca", true)
    : (hasScaFlag ? parsed.sca : defaultScan);

  const scanHygiene = isGitHubActions
    ? getActionBooleanInput("scan-hygiene", true)
    : (hasHygieneFlag ? parsed.hygiene : defaultScan);

  const maxFileSizeMbStr = isGitHubActions
    ? getActionInput("max-file-size-mb", parsed["max-file-size"])
    : parsed["max-file-size"];
  const maxFileSizeMb = Math.max(1, parseFloat(maxFileSizeMbStr) || 10);

  const requireLicense = isGitHubActions
    ? getActionBooleanInput("require-license", false)
    : (parsed["require-license"] ?? false);

  const failOnCritical = isGitHubActions
    ? getActionBooleanInput("fail-on-critical", false)
    : (parsed["fail-on-critical"] ?? false);

  const failOnHigh = isGitHubActions
    ? getActionBooleanInput("fail-on-high", false)
    : (parsed["fail-on-high"] ?? false);

  const failOnMedium = isGitHubActions
    ? getActionBooleanInput("fail-on-medium", false)
    : (parsed["fail-on-medium"] ?? false);

  const postPrComment = isGitHubActions
    ? getActionBooleanInput("post-pr-comment", true)
    : (parsed["post-pr-comment"] ?? false);

  const createAnnotations = isGitHubActions
    ? getActionBooleanInput("create-annotations", true)
    : (parsed.annotations ?? false);

  const outputDir = isGitHubActions
    ? getActionInput("output-dir", parsed["output-dir"])
    : parsed["output-dir"];

  const githubToken = isGitHubActions
    ? (getActionInput("github-token", "") || Deno.env.get("GITHUB_TOKEN"))
    : (parsed["github-token"] || Deno.env.get("GITHUB_TOKEN"));

  const semgrepRules = isGitHubActions
    ? getActionInput("semgrep-rules", parsed["semgrep-rules"])
    : parsed["semgrep-rules"];

  const trivySeverity = isGitHubActions
    ? getActionInput("trivy-severity", parsed["trivy-severity"])
    : parsed["trivy-severity"];

  return {
    targetPath,
    scanSecrets,
    scanSast,
    scanSca,
    scanHygiene,
    maxFileSizeMb,
    requireLicense,
    failOnCritical,
    failOnHigh,
    failOnMedium,
    postPrComment,
    createAnnotations,
    outputDir,
    githubToken,
    semgrepRules,
    trivySeverity,
    verbose: parsed.verbose,
  };
}

export function showHelp(): void {
  console.log(`
Nemesis - Universal Repository Security & Hygiene Auditor (Deno + TypeScript)

USAGE:
  deno run --allow-all src/main.ts [OPTIONS]
  nemesis [OPTIONS]

OPTIONS:
  -p, --path <DIR>          Target directory to audit (default: ".")
      --all                 Enable all scan modules (secrets, sast, sca, hygiene)
      --secrets             Run secret scanning (Gitleaks)
      --sast                Run static application security testing (Semgrep)
      --sca                 Run software composition analysis (Trivy)
      --hygiene             Run repository hygiene & junk cleanup checks
      --max-file-size <MB>  Max file size before warning in MB (default: 10)
      --require-license     Require a LICENSE file in repository root
      --fail-on-critical    Exit with code 1 if CRITICAL vulnerabilities exist
      --fail-on-high        Exit with code 1 if HIGH or CRITICAL exist
      --fail-on-medium      Exit with code 1 if MEDIUM or higher exist
      --post-pr-comment     Post Markdown summary on GitHub PR
      --annotations         Generate GitHub inline code annotations
      --output-dir <DIR>    Directory for report outputs (default: ".nemesis-reports")
      --semgrep-rules <R>   Semgrep rule config (default: "p/security-audit")
      --trivy-severity <S>  Trivy severity filter (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
  -v, --verbose             Print detailed debug logs
  -h, --help                Show this help message
`);
}
