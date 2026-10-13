export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type FindingCategory = "SECRET" | "SAST" | "SCA" | "MISCONFIG" | "HYGIENE" | "LICENSE";

export interface AuditFinding {
  id: string;
  tool: "gitleaks" | "semgrep" | "trivy" | "hygiene" | "license" | string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  endLine?: number;
  column?: number;
  ruleId?: string;
  cve?: string;
  package?: string;
  installedVersion?: string;
  fixedVersion?: string;
  license?: string;
  fileSizeBytes?: number;
  ignored?: boolean;
  ignoreReason?: string;
  suggestedReplacement?: string;
  raw?: unknown;
}

export interface ScannerSummary {
  tool: string;
  category: FindingCategory;
  status: "success" | "failed" | "skipped";
  durationMs: number;
  error?: string;
  counts: Record<Severity, number>;
}

export interface AuditReport {
  timestamp: string;
  targetPath: string;
  repository?: string;
  commitSha?: string;
  pullRequestNumber?: number;
  diffMode?: boolean;
  scanners: ScannerSummary[];
  findings: AuditFinding[];
  ignoredFindings: AuditFinding[];
  totalFindings: number;
  counts: Record<Severity, number>;
  passed: boolean;
  failureReason?: string;
  sbomPath?: string;
  autoFixedCount?: number;
  autoFixCommit?: string;
}

export interface NemesisConfig {
  targetPath: string;
  scanSecrets: boolean;
  scanSast: boolean;
  scanSca: boolean;
  scanHygiene: boolean;
  scanLicenses: boolean;
  generateSbom: boolean;
  diffMode: boolean;
  diffBaseRef: string;
  autoFix: boolean;
  prSuggestions: boolean;
  maxFileSizeMb: number;
  requireLicense: boolean;
  failOnCritical: boolean;
  failOnHigh: boolean;
  failOnMedium: boolean;
  postPrComment: boolean;
  createAnnotations: boolean;
  outputDir: string;
  githubToken?: string;
  semgrepRules: string;
  trivySeverity: string;
  slackWebhookUrl?: string;
  discordWebhookUrl?: string;
  configFile?: string;
  changedFiles?: string[];
  verbose: boolean;
}
