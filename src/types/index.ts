/**
 * Core Type Definitions for Code Review System
 */

export interface AnalysisTarget {
  type: 'url' | 'repository' | 'local';
  value: string;
  branch?: string;
  credentials?: {
    username?: string;
    token?: string;
  };
}

export interface AnalysisConfig {
  security: SecurityConfig;
  performance: PerformanceConfig;
  codeQuality: CodeQualityConfig;
  seo: SEOConfig;
  accessibility: AccessibilityConfig;
  reporting: ReportingConfig;
  notifications?: NotificationConfig;
}

export interface SecurityConfig {
  enabled: boolean;
  scanDepth: 'shallow' | 'medium' | 'deep';
  excludePatterns: string[];
  sensitiveDataPatterns: string[];
  osint: {
    enabled: boolean;
    checkDependencies: boolean;
    checkGitHistory: boolean;
  };
  vulnerabilityThresholds: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface PerformanceConfig {
  enabled: boolean;
  lighthouseConfig: {
    formFactor: 'mobile' | 'desktop';
    throttling: '4G' | '3G' | 'none';
    onlyCategories?: string[];
  };
  thresholds: {
    performance: number;
    accessibility: number;
    bestPractices: number;
    seo: number;
  };
}

export interface CodeQualityConfig {
  enabled: boolean;
  languages: string[];
  complexityThreshold: number;
  duplicateThreshold: number;
  checkTests: boolean;
  checkDocumentation: boolean;
}

export interface SEOConfig {
  enabled: boolean;
  checkMobileFriendly: boolean;
  checkStructuredData: boolean;
  checkSitemap: boolean;
  checkRobotsTxt: boolean;
}

export interface AccessibilityConfig {
  enabled: boolean;
  wcagLevel: 'A' | 'AA' | 'AAA';
  checkARIA: boolean;
  checkContrast: boolean;
  checkKeyboardNav: boolean;
}

export interface ReportingConfig {
  formats: ReportFormat[];
  outputDir: string;
  includeMetrics: boolean;
  executiveSummary: boolean;
  detailedFindings: boolean;
}

export type ReportFormat = 'html' | 'pdf' | 'markdown' | 'json' | 'gama' | 'pptx';

export interface NotificationConfig {
  slack?: {
    enabled: boolean;
    webhook: string;
    channel?: string;
  };
  email?: {
    enabled: boolean;
    recipients: string[];
    smtp?: {
      host: string;
      port: number;
      secure: boolean;
      auth: {
        user: string;
        pass: string;
      };
    };
  };
  webhook?: {
    enabled: boolean;
    url: string;
    headers?: Record<string, string>;
  };
}

export interface AnalysisResults {
  id: string;
  timestamp: Date;
  target: AnalysisTarget;
  overallScore: number;
  scores: {
    security: number;
    performance: number;
    codeQuality: number;
    seo: number;
    accessibility: number;
  };
  security: SecurityResults;
  performance: PerformanceResults;
  codeQuality: CodeQualityResults;
  seo: SEOResults;
  accessibility: AccessibilityResults;
  summary: ResultSummary;
  recommendations: Recommendation[];
}

export interface SecurityResults {
  score: number;
  vulnerabilities: Vulnerability[];
  sensitiveData: SensitiveDataFinding[];
  headers: HeaderAnalysis;
  osint: OSINTFindings;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface Vulnerability {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: {
    file: string;
    line?: number;
    column?: number;
  };
  cwe?: string;
  owasp?: string;
  remediation: string;
  references: string[];
  confidence: 'high' | 'medium' | 'low';
}

export interface SensitiveDataFinding {
  type: 'api-key' | 'password' | 'token' | 'secret' | 'credential';
  pattern: string;
  location: {
    file: string;
    line: number;
  };
  masked: string;
  severity: 'critical' | 'high' | 'medium';
}

export interface HeaderAnalysis {
  score: number;
  headers: {
    name: string;
    present: boolean;
    value?: string;
    recommendation?: string;
  }[];
  cors: {
    enabled: boolean;
    configuration: any;
    issues: string[];
  };
  cookies: {
    secure: boolean;
    httpOnly: boolean;
    sameSite: boolean;
    issues: string[];
  };
}

export interface OSINTFindings {
  dependencies: DependencyVulnerability[];
  gitHistory: GitHistoryIssue[];
  domainReputation?: {
    score: number;
    blacklisted: boolean;
    issues: string[];
  };
  certificateInfo?: {
    valid: boolean;
    expiryDate: Date;
    issuer: string;
    issues: string[];
  };
}

export interface DependencyVulnerability {
  package: string;
  version: string;
  vulnerabilities: {
    id: string;
    severity: string;
    title: string;
    url: string;
  }[];
  recommendation: string;
}

export interface GitHistoryIssue {
  commit: string;
  type: 'sensitive-data' | 'large-file' | 'security-issue';
  description: string;
  file?: string;
}

export interface PerformanceResults {
  score: number;
  lighthouse: LighthouseResults;
  coreWebVitals: CoreWebVitals;
  resourceAnalysis: ResourceAnalysis;
  recommendations: string[];
}

export interface LighthouseResults {
  performance: number;
  accessibility: number;
  bestPractices: number;
  seo: number;
  pwa?: number;
  audits: Record<string, any>;
}

export interface CoreWebVitals {
  lcp: { value: number; rating: 'good' | 'needs-improvement' | 'poor' };
  fid: { value: number; rating: 'good' | 'needs-improvement' | 'poor' };
  cls: { value: number; rating: 'good' | 'needs-improvement' | 'poor' };
  fcp: { value: number; rating: 'good' | 'needs-improvement' | 'poor' };
  ttfb: { value: number; rating: 'good' | 'needs-improvement' | 'poor' };
}

export interface ResourceAnalysis {
  totalSize: number;
  requests: number;
  breakdown: {
    javascript: number;
    css: number;
    images: number;
    fonts: number;
    other: number;
  };
  optimizations: {
    type: string;
    savings: number;
    description: string;
  }[];
}

export interface CodeQualityResults {
  score: number;
  maintainabilityIndex: number;
  technicalDebt: {
    ratio: number;
    hours: number;
  };
  codeSmells: CodeSmell[];
  duplication: DuplicationResult;
  complexity: ComplexityResult;
  testCoverage?: TestCoverageResult;
  documentation: DocumentationResult;
}

export interface CodeSmell {
  type: string;
  severity: 'high' | 'medium' | 'low';
  location: {
    file: string;
    startLine: number;
    endLine: number;
  };
  description: string;
  suggestion: string;
}

export interface DuplicationResult {
  percentage: number;
  blocks: {
    files: string[];
    lines: number;
    tokens: number;
  }[];
}

export interface ComplexityResult {
  average: number;
  highest: {
    file: string;
    function: string;
    complexity: number;
  }[];
}

export interface TestCoverageResult {
  overall: number;
  statements: number;
  branches: number;
  functions: number;
  lines: number;
}

export interface DocumentationResult {
  score: number;
  coverage: number;
  issues: {
    file: string;
    type: string;
    description: string;
  }[];
}

export interface SEOResults {
  score: number;
  technical: TechnicalSEO;
  content: ContentSEO;
  mobile: MobileSEO;
  issues: SEOIssue[];
}

export interface TechnicalSEO {
  score: number;
  sitemap: { present: boolean; valid: boolean; url?: string };
  robotsTxt: { present: boolean; valid: boolean; issues: string[] };
  canonicalUrls: { implemented: boolean; issues: string[] };
  structuredData: { present: boolean; types: string[]; errors: string[] };
}

export interface ContentSEO {
  score: number;
  titles: { present: boolean; optimal: boolean; length: number; issues: string[] };
  descriptions: { present: boolean; optimal: boolean; length: number; issues: string[] };
  headings: { structure: string; issues: string[] };
  images: { totalImages: number; withAlt: number; issues: string[] };
}

export interface MobileSEO {
  score: number;
  responsive: boolean;
  viewport: { configured: boolean; value?: string };
  touchTargets: { adequate: boolean; issues: string[] };
  textSize: { readable: boolean; issues: string[] };
}

export interface SEOIssue {
  type: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  recommendation: string;
  impact: string;
}

export interface AccessibilityResults {
  score: number;
  wcagCompliance: {
    level: 'A' | 'AA' | 'AAA';
    percentage: number;
  };
  violations: AccessibilityViolation[];
  warnings: AccessibilityViolation[];
  screenReader: ScreenReaderResult;
  keyboard: KeyboardNavigationResult;
  visual: VisualAccessibilityResult;
}

export interface AccessibilityViolation {
  id: string;
  impact: 'critical' | 'serious' | 'moderate' | 'minor';
  wcagCriteria: string[];
  description: string;
  nodes: {
    html: string;
    target: string[];
  }[];
  remediation: string;
}

export interface ScreenReaderResult {
  score: number;
  ariaLabels: { present: number; missing: number; invalid: number };
  landmarks: { present: boolean; appropriate: boolean };
  altText: { present: number; missing: number; decorative: number };
}

export interface KeyboardNavigationResult {
  score: number;
  focusable: boolean;
  skipLinks: boolean;
  tabOrder: { logical: boolean; issues: string[] };
  focusIndicators: { visible: boolean; issues: string[] };
}

export interface VisualAccessibilityResult {
  score: number;
  colorContrast: {
    passed: number;
    failed: number;
    issues: { element: string; ratio: number; required: number }[];
  };
  textScaling: { supported: boolean; issues: string[] };
  animations: { respectsPreference: boolean; issues: string[] };
}

export interface ResultSummary {
  overallHealth: string; // 'excellent' | 'good' | 'needs-improvement' | 'poor'
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  strengths: string[];
  weaknesses: string[];
  quickWins: string[];
}

export interface Recommendation {
  id: string;
  category: 'security' | 'performance' | 'code-quality' | 'seo' | 'accessibility';
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  impact: string;
  effort: 'high' | 'medium' | 'low';
  steps: string[];
  resources: string[];
  estimatedTime: string;
}

export interface ScanProgress {
  phase: 'initialization' | 'security' | 'performance' | 'code-quality' | 'seo' | 'accessibility' | 'reporting';
  percentage: number;
  message: string;
  details?: string;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface Logger {
  debug(message: string, ...args: any[]): void;
  info(message: string, ...args: any[]): void;
  warn(message: string, ...args: any[]): void;
  error(message: string, ...args: any[]): void;
}