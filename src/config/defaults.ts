import { AnalysisConfig } from '../types';

export const defaultConfig: AnalysisConfig = {
  security: {
    enabled: true,
    scanDepth: 'medium',
    excludePatterns: [
      'node_modules/**',
      'dist/**',
      'build/**',
      '.git/**',
      'vendor/**',
      '*.min.js',
      '*.min.css'
    ],
    sensitiveDataPatterns: [
      'api[_-]?key',
      'api[_-]?secret',
      'access[_-]?token',
      'auth[_-]?token',
      'secret[_-]?key',
      'private[_-]?key',
      'client[_-]?secret',
      'password',
      'pwd',
      'passwd',
      'database[_-]?url',
      'connection[_-]?string',
      'aws[_-]?access[_-]?key',
      'aws[_-]?secret[_-]?key',
      'stripe[_-]?key',
      'twilio[_-]?token',
      'bearer',
      'authorization'
    ],
    osint: {
      enabled: true,
      checkDependencies: true,
      checkGitHistory: true
    },
    vulnerabilityThresholds: {
      critical: 0,
      high: 3,
      medium: 10,
      low: 20
    }
  },
  performance: {
    enabled: true,
    lighthouseConfig: {
      formFactor: 'mobile',
      throttling: '4G',
      onlyCategories: ['performance', 'accessibility', 'best-practices', 'seo']
    },
    thresholds: {
      performance: 70,
      accessibility: 80,
      bestPractices: 80,
      seo: 80
    }
  },
  codeQuality: {
    enabled: true,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php'],
    complexityThreshold: 15,
    duplicateThreshold: 5,
    checkTests: true,
    checkDocumentation: true
  },
  seo: {
    enabled: true,
    checkMobileFriendly: true,
    checkStructuredData: true,
    checkSitemap: true,
    checkRobotsTxt: true
  },
  accessibility: {
    enabled: true,
    wcagLevel: 'AA',
    checkARIA: true,
    checkContrast: true,
    checkKeyboardNav: true
  },
  reporting: {
    formats: ['html', 'json'],
    outputDir: './reports',
    includeMetrics: true,
    executiveSummary: true,
    detailedFindings: true
  }
};

export const securityPatterns = {
  sqlInjection: [
    /execute\s*\(\s*["'].*\+.*["']\s*\)/gi,
    /query\s*\(\s*["'].*\+.*["']\s*\)/gi,
    /SELECT.*FROM.*WHERE.*\+/gi
  ],
  xss: [
    /innerHTML\s*=\s*.*\+/gi,
    /document\.write\s*\(/gi,
    /eval\s*\(/gi,
    /<script>.*<\/script>/gi
  ],
  hardcodedSecrets: [
    /['"]([A-Za-z0-9]{32,})['"][\s]*[:=]/g, // Generic 32+ char strings
    /['"]?(sk_live_[A-Za-z0-9]{24,})['"]?/g, // Stripe Live Key
    /['"]?(sk_test_[A-Za-z0-9]{24,})['"]?/g, // Stripe Test Key
    /['"]?(AKIA[0-9A-Z]{16})['"]?/g, // AWS Access Key
    /['"]?([0-9a-zA-Z/+]{40})['"]?\s*[:=]\s*['"]?aws_secret/gi, // AWS Secret Key
    /['"]?(ghp_[a-zA-Z0-9]{36})['"]?/g, // GitHub Personal Access Token
    /['"]?(gho_[a-zA-Z0-9]{36})['"]?/g, // GitHub OAuth Token
    /['"]?(glpat-[a-zA-Z0-9_-]{20})['"]?/g, // GitLab Personal Access Token
    /['"]?([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)['"]?/g, // Google OAuth
    /['"]?(AIza[0-9A-Za-z_-]{35})['"]?/g, // Google API Key
    /['"]?(ya29\.[0-9A-Za-z_-]+)['"]?/g, // Google OAuth Access Token
    /['"]?(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9A-Za-z]{24,32})['"]?/g // Slack Token
  ],
  unsafeDeserialization: [
    /pickle\.loads\(/gi,
    /yaml\.load\(/gi,
    /JSON\.parse\s*\(\s*.*user/gi
  ],
  commandInjection: [
    /exec\s*\(\s*.*\+/gi,
    /system\s*\(\s*.*\+/gi,
    /shell_exec\s*\(/gi,
    /spawn\s*\(\s*.*\+/gi
  ]
};

export const securityHeaders = [
  {
    name: 'Content-Security-Policy',
    description: 'Prevents XSS and data injection attacks',
    recommended: "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'",
    severity: 'high'
  },
  {
    name: 'X-Frame-Options',
    description: 'Prevents clickjacking attacks',
    recommended: 'DENY or SAMEORIGIN',
    severity: 'medium'
  },
  {
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME-sniffing',
    recommended: 'nosniff',
    severity: 'medium'
  },
  {
    name: 'Strict-Transport-Security',
    description: 'Forces HTTPS connections',
    recommended: 'max-age=31536000; includeSubDomains',
    severity: 'high'
  },
  {
    name: 'X-XSS-Protection',
    description: 'Enables browser XSS protection',
    recommended: '1; mode=block',
    severity: 'low'
  },
  {
    name: 'Referrer-Policy',
    description: 'Controls referrer information',
    recommended: 'strict-origin-when-cross-origin',
    severity: 'low'
  },
  {
    name: 'Permissions-Policy',
    description: 'Controls browser features',
    recommended: 'geolocation=(), microphone=(), camera=()',
    severity: 'medium'
  }
];

export const cweMapping: Record<string, string> = {
  'sql-injection': 'CWE-89',
  'xss': 'CWE-79',
  'csrf': 'CWE-352',
  'xxe': 'CWE-611',
  'insecure-deserialization': 'CWE-502',
  'broken-authentication': 'CWE-287',
  'sensitive-data-exposure': 'CWE-200',
  'missing-access-control': 'CWE-284',
  'security-misconfiguration': 'CWE-16',
  'broken-access-control': 'CWE-639',
  'command-injection': 'CWE-78',
  'path-traversal': 'CWE-22',
  'open-redirect': 'CWE-601',
  'ssrf': 'CWE-918'
};

export const owaspTop10Mapping: Record<string, string> = {
  'broken-access-control': 'A01:2021',
  'cryptographic-failures': 'A02:2021',
  'injection': 'A03:2021',
  'insecure-design': 'A04:2021',
  'security-misconfiguration': 'A05:2021',
  'vulnerable-components': 'A06:2021',
  'authentication-failures': 'A07:2021',
  'data-integrity-failures': 'A08:2021',
  'logging-monitoring-failures': 'A09:2021',
  'ssrf': 'A10:2021'
};