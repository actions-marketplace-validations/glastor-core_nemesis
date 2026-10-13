export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type FindingCategory = "SECRET" | "SAST" | "SCA" | "MISCONFIG" | "HYGIENE";

export interface AuditFinding {
  id: string;
  tool: "gitleaks" | "semgrep" | "trivy" | "hygiene" | string;
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
  fileSizeBytes?: number;
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
  scanners: ScannerSummary[];
  findings: AuditFinding[];
  totalFindings: number;
  counts: Record<Severity, number>;
  passed: boolean;
  failureReason?: string;
}

export interface NemesisConfig {
  targetPath: string;
  scanSecrets: boolean;
  scanSast: boolean;
  scanSca: boolean;
  scanHygiene: boolean;
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
  verbose: boolean;
}
