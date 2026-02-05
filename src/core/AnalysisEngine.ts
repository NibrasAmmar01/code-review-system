import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  AnalysisTarget,
  AnalysisConfig,
  AnalysisResults,
  ScanProgress,
  Logger
} from '../types';
import { SecurityScanner } from '../modules/security/SecurityScanner';
import { PerformanceAnalyzer } from '../modules/performance/PerformanceAnalyzer';
import { CodeQualityAnalyzer } from '../modules/code-quality/CodeQualityAnalyzer';
import { SEOAnalyzer } from '../modules/seo/SEOAnalyzer';
import { AccessibilityAnalyzer } from '../modules/accessibility/AccessibilityAnalyzer';
import { ReportGenerator } from '../reporters/ReportGenerator';
import { Logger as WinstonLogger } from '../utils/Logger';
import { validateConfig } from '../utils/validators';
import { calculateOverallScore, generateRecommendations } from '../utils/scoring';

export class AnalysisEngine extends EventEmitter {
  private logger: Logger;
  private securityScanner: SecurityScanner;
  private performanceAnalyzer: PerformanceAnalyzer;
  private codeQualityAnalyzer: CodeQualityAnalyzer;
  private seoAnalyzer: SEOAnalyzer;
  private accessibilityAnalyzer: AccessibilityAnalyzer;
  private reportGenerator: ReportGenerator;

  constructor(private config: AnalysisConfig) {
    super();
    this.logger = new WinstonLogger();
    this.validateConfiguration();
    this.initializeModules();
  }

  private validateConfiguration(): void {
    const validation = validateConfig(this.config);
    if (!validation.valid) {
      throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
    }
    this.logger.info('Configuration validated successfully');
  }

  private initializeModules(): void {
    this.securityScanner = new SecurityScanner(this.config.security, this.logger);
    this.performanceAnalyzer = new PerformanceAnalyzer(this.config.performance, this.logger);
    this.codeQualityAnalyzer = new CodeQualityAnalyzer(this.config.codeQuality, this.logger);
    this.seoAnalyzer = new SEOAnalyzer(this.config.seo, this.logger);
    this.accessibilityAnalyzer = new AccessibilityAnalyzer(
      this.config.accessibility,
      this.logger
    );
    this.reportGenerator = new ReportGenerator(this.config.reporting, this.logger);
    this.logger.info('Analysis modules initialized');
  }

  /**
   * Main analysis execution method
   */
  public async analyze(target: AnalysisTarget): Promise<AnalysisResults> {
    const analysisId = uuidv4();
    const startTime = Date.now();

    try {
      this.logger.info(`Starting analysis ${analysisId} for target: ${target.value}`);
      this.emitProgress({ phase: 'initialization', percentage: 0, message: 'Initializing analysis' });

      // Phase 1: Security Analysis
      let securityResults = null;
      if (this.config.security.enabled) {
        this.emitProgress({
          phase: 'security',
          percentage: 10,
          message: 'Running security scan...'
        });
        securityResults = await this.securityScanner.scan(target);
        this.logger.info(`Security scan completed: ${securityResults.vulnerabilities.length} vulnerabilities found`);
      }

      // Phase 2: Performance Analysis
      let performanceResults = null;
      if (this.config.performance.enabled && target.type === 'url') {
        this.emitProgress({
          phase: 'performance',
          percentage: 30,
          message: 'Analyzing performance with Lighthouse...'
        });
        performanceResults = await this.performanceAnalyzer.analyze(target);
        this.logger.info(`Performance analysis completed: score ${performanceResults.score}`);
      }

      // Phase 3: Code Quality Analysis
      let codeQualityResults = null;
      if (this.config.codeQuality.enabled && target.type !== 'url') {
        this.emitProgress({
          phase: 'code-quality',
          percentage: 50,
          message: 'Analyzing code quality...'
        });
        codeQualityResults = await this.codeQualityAnalyzer.analyze(target);
        this.logger.info(`Code quality analysis completed: maintainability ${codeQualityResults.maintainabilityIndex}`);
      }

      // Phase 4: SEO Analysis
      let seoResults = null;
      if (this.config.seo.enabled && target.type === 'url') {
        this.emitProgress({
          phase: 'seo',
          percentage: 70,
          message: 'Analyzing SEO factors...'
        });
        seoResults = await this.seoAnalyzer.analyze(target);
        this.logger.info(`SEO analysis completed: score ${seoResults.score}`);
      }

      // Phase 5: Accessibility Analysis
      let accessibilityResults = null;
      if (this.config.accessibility.enabled && target.type === 'url') {
        this.emitProgress({
          phase: 'accessibility',
          percentage: 85,
          message: 'Checking accessibility compliance...'
        });
        accessibilityResults = await this.accessibilityAnalyzer.analyze(target);
        this.logger.info(`Accessibility analysis completed: score ${accessibilityResults.score}`);
      }

      // Phase 6: Calculate Scores and Generate Recommendations
      this.emitProgress({
        phase: 'reporting',
        percentage: 95,
        message: 'Generating report and recommendations...'
      });

      const scores = {
        security: securityResults?.score || 0,
        performance: performanceResults?.score || 0,
        codeQuality: codeQualityResults?.score || 0,
        seo: seoResults?.score || 0,
        accessibility: accessibilityResults?.score || 0
      };

      const overallScore = calculateOverallScore(scores, this.config);

      const results: AnalysisResults = {
        id: analysisId,
        timestamp: new Date(),
        target,
        overallScore,
        scores,
        security: securityResults!,
        performance: performanceResults!,
        codeQuality: codeQualityResults!,
        seo: seoResults!,
        accessibility: accessibilityResults!,
        summary: this.generateSummary(scores, securityResults, performanceResults, codeQualityResults),
        recommendations: generateRecommendations(
          securityResults,
          performanceResults,
          codeQualityResults,
          seoResults,
          accessibilityResults
        )
      };

      // Generate Reports
      if (this.config.reporting.formats.length > 0) {
        await this.reportGenerator.generate(results);
      }

      this.emitProgress({
        phase: 'reporting',
        percentage: 100,
        message: 'Analysis completed successfully'
      });

      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      this.logger.info(`Analysis ${analysisId} completed in ${duration}s`);

      return results;
    } catch (error) {
      this.logger.error(`Analysis ${analysisId} failed:`, error);
      throw error;
    }
  }

  private generateSummary(scores: any, securityResults: any, performanceResults: any, codeQualityResults: any): any {
    const avgScore = Object.values(scores).reduce((a: any, b: any) => a + b, 0) / Object.values(scores).filter(s => s > 0).length;
    
    let overallHealth: string;
    if (avgScore >= 90) overallHealth = 'excellent';
    else if (avgScore >= 70) overallHealth = 'good';
    else if (avgScore >= 50) overallHealth = 'needs-improvement';
    else overallHealth = 'poor';

    const criticalIssues = securityResults?.summary.critical || 0;
    const highIssues = securityResults?.summary.high || 0;
    const mediumIssues = securityResults?.summary.medium || 0;
    const lowIssues = securityResults?.summary.low || 0;

    const strengths: string[] = [];
    const weaknesses: string[] = [];
    const quickWins: string[] = [];

    if (scores.security >= 80) strengths.push('Strong security posture');
    else if (scores.security < 50) weaknesses.push('Critical security vulnerabilities detected');

    if (scores.performance >= 80) strengths.push('Excellent performance metrics');
    else if (scores.performance < 50) {
      weaknesses.push('Poor performance scores');
      quickWins.push('Optimize images and enable compression');
    }

    if (scores.codeQuality >= 80) strengths.push('High code quality standards');
    else if (scores.codeQuality < 50) {
      weaknesses.push('Code maintainability issues');
      quickWins.push('Refactor complex functions and remove duplication');
    }

    return {
      overallHealth,
      criticalIssues,
      highIssues,
      mediumIssues,
      lowIssues,
      strengths,
      weaknesses,
      quickWins
    };
  }

  private emitProgress(progress: ScanProgress): void {
    this.emit('progress', progress);
  }

  /**
   * Cancel ongoing analysis
   */
  public cancel(): void {
    this.logger.warn('Analysis cancelled by user');
    this.emit('cancelled');
  }

  /**
   * Get current analysis status
   */
  public getStatus(): any {
    return {
      running: true,
      modules: {
        security: this.config.security.enabled,
        performance: this.config.performance.enabled,
        codeQuality: this.config.codeQuality.enabled,
        seo: this.config.seo.enabled,
        accessibility: this.config.accessibility.enabled
      }
    };
  }
}