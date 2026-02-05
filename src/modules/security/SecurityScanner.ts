import * as fs from 'fs/promises';
import * as path from 'path';
import { glob } from 'glob';
import axios from 'axios';
import {
  AnalysisTarget,
  SecurityConfig,
  SecurityResults,
  Vulnerability,
  SensitiveDataFinding,
  Logger
} from '../../types';
import { securityPatterns, securityHeaders, cweMapping, owaspTop10Mapping } from '../../config/defaults';

export class SecurityScanner {
  constructor(
    private config: SecurityConfig,
    private logger: Logger
  ) {}

  public async scan(target: AnalysisTarget): Promise<SecurityResults> {
    this.logger.info('Starting security scan');

    const vulnerabilities: Vulnerability[] = [];
    const sensitiveData: SensitiveDataFinding[] = [];
    let headerAnalysis: any = null;
    let osintFindings: any = null;

    try {
      // Scan for vulnerabilities based on target type
      if (target.type === 'url') {
        vulnerabilities.push(...await this.scanWebApplication(target.value));
        headerAnalysis = await this.analyzeHeaders(target.value);
      } else {
        vulnerabilities.push(...await this.scanSourceCode(target.value));
      }

      // Scan for sensitive data
      sensitiveData.push(...await this.scanSensitiveData(target));

      // OSINT analysis
      if (this.config.osint.enabled) {
        osintFindings = await this.performOSINT(target);
      }

      // Calculate severity summary
      const summary = {
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length,
        info: vulnerabilities.filter(v => v.severity === 'info').length
      };

      // Calculate security score
      const score = this.calculateSecurityScore(summary, sensitiveData.length, headerAnalysis);

      return {
        score,
        vulnerabilities,
        sensitiveData,
        headers: headerAnalysis || this.getDefaultHeaderAnalysis(),
        osint: osintFindings || this.getDefaultOSINTFindings(),
        summary
      };
    } catch (error) {
      this.logger.error('Security scan failed:', error);
      throw error;
    }
  }

  private async scanWebApplication(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    try {
      // Test for common web vulnerabilities
      this.logger.debug(`Scanning web application: ${url}`);

      // Check for XSS vulnerabilities
      const xssVulns = await this.checkXSS(url);
      vulnerabilities.push(...xssVulns);

      // Check for SQL injection
      const sqlVulns = await this.checkSQLInjection(url);
      vulnerabilities.push(...sqlVulns);

      // Check for security misconfigurations
      const misconfigVulns = await this.checkSecurityMisconfigurations(url);
      vulnerabilities.push(...misconfigVulns);

      // Check for open redirects
      const redirectVulns = await this.checkOpenRedirects(url);
      vulnerabilities.push(...redirectVulns);

    } catch (error) {
      this.logger.error('Web application scan failed:', error);
    }

    return vulnerabilities;
  }

  private async scanSourceCode(sourcePath: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    try {
      this.logger.debug(`Scanning source code: ${sourcePath}`);

      // Get all relevant files
      const files = await this.getSourceFiles(sourcePath);

      for (const file of files) {
        const content = await fs.readFile(file, 'utf-8');
        
        // Check for SQL injection patterns
        vulnerabilities.push(...this.detectSQLInjection(file, content));

        // Check for XSS vulnerabilities
        vulnerabilities.push(...this.detectXSS(file, content));

        // Check for command injection
        vulnerabilities.push(...this.detectCommandInjection(file, content));

        // Check for insecure deserialization
        vulnerabilities.push(...this.detectInsecureDeserialization(file, content));

        // Check for hardcoded credentials
        vulnerabilities.push(...this.detectHardcodedCredentials(file, content));
      }
    } catch (error) {
      this.logger.error('Source code scan failed:', error);
    }

    return vulnerabilities;
  }

  private async scanSensitiveData(target: AnalysisTarget): Promise<SensitiveDataFinding[]> {
    const findings: SensitiveDataFinding[] = [];

    try {
      const sourcePath = target.type === 'url' ? '.' : target.value;
      const files = await this.getSourceFiles(sourcePath);

      for (const file of files) {
        // Skip binary files and large files
        const stats = await fs.stat(file);
        if (stats.size > 1024 * 1024 * 10) continue; // Skip files > 10MB

        try {
          const content = await fs.readFile(file, 'utf-8');
          const lines = content.split('\n');

          // Check each pattern
          for (const pattern of this.config.sensitiveDataPatterns) {
            const regex = new RegExp(pattern, 'gi');
            let match;

            lines.forEach((line, index) => {
              while ((match = regex.exec(line)) !== null) {
                const matched = match[0];
                
                // Skip if it's a comment or looks like a placeholder
                if (this.isLikelyFalsePositive(line, matched)) continue;

                findings.push({
                  type: this.categorizeSensitiveData(matched),
                  pattern: pattern,
                  location: {
                    file: file,
                    line: index + 1
                  },
                  masked: this.maskSensitiveData(matched),
                  severity: this.getSeverityForDataType(matched)
                });
              }
            });
          }

          // Check for hardcoded secrets using specialized patterns
          for (const pattern of securityPatterns.hardcodedSecrets) {
            let match;
            while ((match = pattern.exec(content)) !== null) {
              const lineNumber = content.substring(0, match.index).split('\n').length;
              
              findings.push({
                type: 'secret',
                pattern: pattern.source,
                location: {
                  file: file,
                  line: lineNumber
                },
                masked: this.maskSensitiveData(match[1] || match[0]),
                severity: 'critical'
              });
            }
          }
        } catch (readError) {
          // Skip files that can't be read as text
          continue;
        }
      }
    } catch (error) {
      this.logger.error('Sensitive data scan failed:', error);
    }

    return findings;
  }

  private async analyzeHeaders(url: string): Promise<any> {
    try {
      const response = await axios.get(url, {
        maxRedirects: 0,
        validateStatus: () => true
      });

      const headers = response.headers;
      const headerResults = securityHeaders.map(header => ({
        name: header.name,
        present: !!headers[header.name.toLowerCase()],
        value: headers[header.name.toLowerCase()],
        recommendation: header.recommended
      }));

      // Check CORS configuration
      const corsConfig = {
        enabled: !!headers['access-control-allow-origin'],
        configuration: {
          origin: headers['access-control-allow-origin'],
          credentials: headers['access-control-allow-credentials'],
          methods: headers['access-control-allow-methods']
        },
        issues: []
      };

      if (headers['access-control-allow-origin'] === '*' && headers['access-control-allow-credentials'] === 'true') {
        corsConfig.issues.push('Insecure CORS: wildcard origin with credentials');
      }

      // Check cookie security
      const setCookie = headers['set-cookie'] || [];
      const cookieAnalysis = {
        secure: false,
        httpOnly: false,
        sameSite: false,
        issues: []
      };

      if (Array.isArray(setCookie)) {
        cookieAnalysis.secure = setCookie.some(c => c.toLowerCase().includes('secure'));
        cookieAnalysis.httpOnly = setCookie.some(c => c.toLowerCase().includes('httponly'));
        cookieAnalysis.sameSite = setCookie.some(c => c.toLowerCase().includes('samesite'));

        if (!cookieAnalysis.secure) cookieAnalysis.issues.push('Cookies not marked as Secure');
        if (!cookieAnalysis.httpOnly) cookieAnalysis.issues.push('Cookies not marked as HttpOnly');
        if (!cookieAnalysis.sameSite) cookieAnalysis.issues.push('Cookies missing SameSite attribute');
      }

      const score = this.calculateHeaderScore(headerResults);

      return {
        score,
        headers: headerResults,
        cors: corsConfig,
        cookies: cookieAnalysis
      };
    } catch (error) {
      this.logger.error('Header analysis failed:', error);
      return this.getDefaultHeaderAnalysis();
    }
  }

  private async performOSINT(target: AnalysisTarget): Promise<any> {
    const findings: any = {
      dependencies: [],
      gitHistory: [],
      domainReputation: null,
      certificateInfo: null
    };

    try {
      // Check for dependency vulnerabilities
      if (this.config.osint.checkDependencies) {
        findings.dependencies = await this.checkDependencyVulnerabilities(target);
      }

      // Check git history for secrets
      if (this.config.osint.checkGitHistory && target.type !== 'url') {
        findings.gitHistory = await this.checkGitHistory(target.value);
      }

      // For URL targets, check domain reputation and certificate
      if (target.type === 'url') {
        findings.domainReputation = await this.checkDomainReputation(target.value);
        findings.certificateInfo = await this.checkCertificate(target.value);
      }
    } catch (error) {
      this.logger.error('OSINT analysis failed:', error);
    }

    return findings;
  }

  private detectSQLInjection(file: string, content: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const patterns = securityPatterns.sqlInjection;

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        vulnerabilities.push({
          id: `sql-injection-${file}-${lineNumber}`,
          type: 'sql-injection',
          severity: 'high',
          title: 'Potential SQL Injection Vulnerability',
          description: 'SQL query construction using string concatenation detected. This may lead to SQL injection attacks.',
          location: {
            file,
            line: lineNumber
          },
          cwe: cweMapping['sql-injection'],
          owasp: owaspTop10Mapping['injection'],
          remediation: 'Use parameterized queries or prepared statements instead of string concatenation.',
          references: [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cwe.mitre.org/data/definitions/89.html'
          ],
          confidence: 'medium'
        });
      }
    });

    return vulnerabilities;
  }

  private detectXSS(file: string, content: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const patterns = securityPatterns.xss;

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        vulnerabilities.push({
          id: `xss-${file}-${lineNumber}`,
          type: 'xss',
          severity: 'high',
          title: 'Potential Cross-Site Scripting (XSS) Vulnerability',
          description: 'User input may be rendered without proper sanitization, leading to XSS attacks.',
          location: {
            file,
            line: lineNumber
          },
          cwe: cweMapping['xss'],
          owasp: owaspTop10Mapping['injection'],
          remediation: 'Sanitize and encode all user input before rendering. Use Content Security Policy headers.',
          references: [
            'https://owasp.org/www-community/attacks/xss/',
            'https://cwe.mitre.org/data/definitions/79.html'
          ],
          confidence: 'medium'
        });
      }
    });

    return vulnerabilities;
  }

  private detectCommandInjection(file: string, content: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const patterns = securityPatterns.commandInjection;

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        vulnerabilities.push({
          id: `command-injection-${file}-${lineNumber}`,
          type: 'command-injection',
          severity: 'critical',
          title: 'Potential Command Injection Vulnerability',
          description: 'System command execution with user-controlled input detected.',
          location: {
            file,
            line: lineNumber
          },
          cwe: cweMapping['command-injection'],
          owasp: owaspTop10Mapping['injection'],
          remediation: 'Avoid executing system commands with user input. If necessary, use whitelisting and proper input validation.',
          references: [
            'https://owasp.org/www-community/attacks/Command_Injection',
            'https://cwe.mitre.org/data/definitions/78.html'
          ],
          confidence: 'high'
        });
      }
    });

    return vulnerabilities;
  }

  private detectInsecureDeserialization(file: string, content: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const patterns = securityPatterns.unsafeDeserialization;

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        vulnerabilities.push({
          id: `insecure-deserialization-${file}-${lineNumber}`,
          type: 'insecure-deserialization',
          severity: 'high',
          title: 'Insecure Deserialization',
          description: 'Unsafe deserialization of untrusted data detected.',
          location: {
            file,
            line: lineNumber
          },
          cwe: cweMapping['insecure-deserialization'],
          owasp: owaspTop10Mapping['data-integrity-failures'],
          remediation: 'Validate and sanitize serialized data. Use safe deserialization methods.',
          references: [
            'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
            'https://cwe.mitre.org/data/definitions/502.html'
          ],
          confidence: 'medium'
        });
      }
    });

    return vulnerabilities;
  }

  private detectHardcodedCredentials(file: string, content: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    
    // Check for common password/credential variable patterns
    const credentialPatterns = [
      /password\s*=\s*["'][^"']+["']/gi,
      /pwd\s*=\s*["'][^"']+["']/gi,
      /api_key\s*=\s*["'][^"']+["']/gi,
      /secret\s*=\s*["'][^"']+["']/gi
    ];

    credentialPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = content.split('\n')[lineNumber - 1];
        
        // Skip if it's a placeholder or environment variable
        if (this.isLikelyFalsePositive(line, match[0])) continue;
        
        vulnerabilities.push({
          id: `hardcoded-credential-${file}-${lineNumber}`,
          type: 'hardcoded-credential',
          severity: 'critical',
          title: 'Hardcoded Credentials Detected',
          description: 'Credentials are hardcoded in source code.',
          location: {
            file,
            line: lineNumber
          },
          cwe: cweMapping['sensitive-data-exposure'],
          owasp: owaspTop10Mapping['cryptographic-failures'],
          remediation: 'Remove hardcoded credentials. Use environment variables or secure credential storage.',
          references: [
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'
          ],
          confidence: 'high'
        });
      }
    });

    return vulnerabilities;
  }

  // Helper methods
  private async getSourceFiles(sourcePath: string): Promise<string[]> {
    const patterns = [
      '**/*.js',
      '**/*.ts',
      '**/*.jsx',
      '**/*.tsx',
      '**/*.py',
      '**/*.java',
      '**/*.php',
      '**/*.rb',
      '**/*.go',
      '**/*.env*',
      '**/*.config.*',
      '**/*.json'
    ];

    const files: string[] = [];
    
    for (const pattern of patterns) {
      const matches = await glob(path.join(sourcePath, pattern), {
        ignore: this.config.excludePatterns
      });
      files.push(...matches);
    }

    return files;
  }

  private isLikelyFalsePositive(line: string, match: string): boolean {
    // Skip comments
    if (line.trim().startsWith('//') || line.trim().startsWith('#') || line.trim().startsWith('*')) {
      return true;
    }

    // Skip placeholders
    const placeholders = ['example', 'placeholder', 'xxx', 'your-', 'todo', 'changeme', 'replace'];
    if (placeholders.some(p => match.toLowerCase().includes(p))) {
      return true;
    }

    // Skip environment variable references
    if (match.includes('process.env') || match.includes('os.getenv') || match.includes('$ENV')) {
      return true;
    }

    return false;
  }

  private categorizeSensitiveData(matched: string): 'api-key' | 'password' | 'token' | 'secret' | 'credential' {
    const lower = matched.toLowerCase();
    if (lower.includes('api') && lower.includes('key')) return 'api-key';
    if (lower.includes('password') || lower.includes('pwd')) return 'password';
    if (lower.includes('token')) return 'token';
    if (lower.includes('secret')) return 'secret';
    return 'credential';
  }

  private getSeverityForDataType(matched: string): 'critical' | 'high' | 'medium' {
    const lower = matched.toLowerCase();
    if (lower.includes('production') || lower.includes('prod') || lower.includes('live')) {
      return 'critical';
    }
    if (lower.includes('api') || lower.includes('secret') || lower.includes('private')) {
      return 'high';
    }
    return 'medium';
  }

  private maskSensitiveData(data: string): string {
    if (data.length <= 8) return '***';
    return data.substring(0, 4) + '***' + data.substring(data.length - 4);
  }

  private async checkXSS(url: string): Promise<Vulnerability[]> {
    // Placeholder for XSS testing
    return [];
  }

  private async checkSQLInjection(url: string): Promise<Vulnerability[]> {
    // Placeholder for SQL injection testing
    return [];
  }

  private async checkSecurityMisconfigurations(url: string): Promise<Vulnerability[]> {
    // Placeholder for security misconfiguration checks
    return [];
  }

  private async checkOpenRedirects(url: string): Promise<Vulnerability[]> {
    // Placeholder for open redirect checks
    return [];
  }

  private async checkDependencyVulnerabilities(target: AnalysisTarget): Promise<any[]> {
    // Placeholder for dependency vulnerability checking
    return [];
  }

  private async checkGitHistory(sourcePath: string): Promise<any[]> {
    // Placeholder for git history analysis
    return [];
  }

  private async checkDomainReputation(url: string): Promise<any> {
    // Placeholder for domain reputation checking
    return null;
  }

  private async checkCertificate(url: string): Promise<any> {
    // Placeholder for certificate checking
    return null;
  }

  private calculateSecurityScore(summary: any, sensitiveDataCount: number, headerAnalysis: any): number {
    let score = 100;

    // Deduct points based on vulnerabilities
    score -= summary.critical * 20;
    score -= summary.high * 10;
    score -= summary.medium * 5;
    score -= summary.low * 2;

    // Deduct points for sensitive data exposure
    score -= sensitiveDataCount * 5;

    // Deduct points for missing security headers
    if (headerAnalysis) {
      const missingHeaders = headerAnalysis.headers.filter((h: any) => !h.present).length;
      score -= missingHeaders * 3;
    }

    return Math.max(0, Math.min(100, score));
  }

  private calculateHeaderScore(headers: any[]): number {
    const presentCount = headers.filter(h => h.present).length;
    return Math.round((presentCount / headers.length) * 100);
  }

  private getDefaultHeaderAnalysis(): any {
    return {
      score: 0,
      headers: [],
      cors: { enabled: false, configuration: {}, issues: [] },
      cookies: { secure: false, httpOnly: false, sameSite: false, issues: [] }
    };
  }

  private getDefaultOSINTFindings(): any {
    return {
      dependencies: [],
      gitHistory: [],
      domainReputation: null,
      certificateInfo: null
    };
  }
}