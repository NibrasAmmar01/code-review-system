import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';
import {
  AnalysisTarget,
  PerformanceConfig,
  PerformanceResults,
  LighthouseResults,
  CoreWebVitals,
  ResourceAnalysis,
  Logger
} from '../../types';

export class PerformanceAnalyzer {
  constructor(
    private config: PerformanceConfig,
    private logger: Logger
  ) {}

  public async analyze(target: AnalysisTarget): Promise<PerformanceResults> {
    if (target.type !== 'url') {
      throw new Error('Performance analysis is only available for URLs');
    }

    this.logger.info(`Starting performance analysis for: ${target.value}`);

    try {
      const lighthouseResults = await this.runLighthouse(target.value);
      const coreWebVitals = this.extractCoreWebVitals(lighthouseResults);
      const resourceAnalysis = this.analyzeResources(lighthouseResults);
      const recommendations = this.generateRecommendations(lighthouseResults);
      
      const score = lighthouseResults.performance;

      return {
        score,
        lighthouse: lighthouseResults,
        coreWebVitals,
        resourceAnalysis,
        recommendations
      };
    } catch (error) {
      this.logger.error('Performance analysis failed:', error);
      throw error;
    }
  }

  private async runLighthouse(url: string): Promise<LighthouseResults> {
    let chrome;
    
    try {
      // Launch Chrome
      chrome = await chromeLauncher.launch({
        chromeFlags: ['--headless', '--disable-gpu', '--no-sandbox']
      });

      // Run Lighthouse
      const options = {
        logLevel: 'error' as const,
        output: 'json' as const,
        onlyCategories: this.config.lighthouseConfig.onlyCategories,
        port: chrome.port,
        formFactor: this.config.lighthouseConfig.formFactor,
        throttling: this.getThrottlingConfig(),
        screenEmulation: {
          mobile: this.config.lighthouseConfig.formFactor === 'mobile',
          width: this.config.lighthouseConfig.formFactor === 'mobile' ? 375 : 1920,
          height: this.config.lighthouseConfig.formFactor === 'mobile' ? 667 : 1080,
          deviceScaleFactor: this.config.lighthouseConfig.formFactor === 'mobile' ? 2 : 1,
          disabled: false
        }
      };

      const runnerResult = await lighthouse(url, options);
      
      if (!runnerResult || !runnerResult.lhr) {
        throw new Error('Lighthouse failed to produce results');
      }

      const lhr = runnerResult.lhr;

      return {
        performance: Math.round(lhr.categories.performance?.score * 100 || 0),
        accessibility: Math.round(lhr.categories.accessibility?.score * 100 || 0),
        bestPractices: Math.round(lhr.categories['best-practices']?.score * 100 || 0),
        seo: Math.round(lhr.categories.seo?.score * 100 || 0),
        pwa: lhr.categories.pwa ? Math.round(lhr.categories.pwa.score * 100) : undefined,
        audits: lhr.audits
      };
    } finally {
      if (chrome) {
        await chrome.kill();
      }
    }
  }

  private extractCoreWebVitals(lighthouseResults: LighthouseResults): CoreWebVitals {
    const audits = lighthouseResults.audits;

    return {
      lcp: this.getMetricWithRating(audits['largest-contentful-paint']),
      fid: this.getMetricWithRating(audits['max-potential-fid']),
      cls: this.getMetricWithRating(audits['cumulative-layout-shift']),
      fcp: this.getMetricWithRating(audits['first-contentful-paint']),
      ttfb: this.getMetricWithRating(audits['server-response-time'])
    };
  }

  private getMetricWithRating(audit: any): { value: number; rating: 'good' | 'needs-improvement' | 'poor' } {
    if (!audit) {
      return { value: 0, rating: 'poor' };
    }

    const value = audit.numericValue || 0;
    let rating: 'good' | 'needs-improvement' | 'poor' = 'good';

    if (audit.score !== null) {
      if (audit.score >= 0.9) rating = 'good';
      else if (audit.score >= 0.5) rating = 'needs-improvement';
      else rating = 'poor';
    }

    return { value, rating };
  }

  private analyzeResources(lighthouseResults: LighthouseResults): ResourceAnalysis {
    const audits = lighthouseResults.audits;
    
    // Extract resource information from audits
    const resourceSummary = audits['resource-summary'];
    const breakdown = {
      javascript: 0,
      css: 0,
      images: 0,
      fonts: 0,
      other: 0
    };

    let totalSize = 0;
    let requests = 0;

    if (resourceSummary && resourceSummary.details && resourceSummary.details.items) {
      resourceSummary.details.items.forEach((item: any) => {
        const size = item.transferSize || 0;
        totalSize += size;
        requests += item.requestCount || 0;

        switch (item.resourceType) {
          case 'script':
            breakdown.javascript += size;
            break;
          case 'stylesheet':
            breakdown.css += size;
            break;
          case 'image':
            breakdown.images += size;
            break;
          case 'font':
            breakdown.fonts += size;
            break;
          default:
            breakdown.other += size;
        }
      });
    }

    // Extract optimization opportunities
    const optimizations: { type: string; savings: number; description: string }[] = [];

    if (audits['unused-javascript']) {
      const savings = audits['unused-javascript'].details?.overallSavingsBytes || 0;
      if (savings > 0) {
        optimizations.push({
          type: 'unused-javascript',
          savings,
          description: 'Remove unused JavaScript to reduce bundle size'
        });
      }
    }

    if (audits['modern-image-formats']) {
      const savings = audits['modern-image-formats'].details?.overallSavingsBytes || 0;
      if (savings > 0) {
        optimizations.push({
          type: 'image-format',
          savings,
          description: 'Use modern image formats like WebP or AVIF'
        });
      }
    }

    if (audits['uses-text-compression']) {
      const savings = audits['uses-text-compression'].details?.overallSavingsBytes || 0;
      if (savings > 0) {
        optimizations.push({
          type: 'text-compression',
          savings,
          description: 'Enable text compression for text-based resources'
        });
      }
    }

    return {
      totalSize,
      requests,
      breakdown,
      optimizations
    };
  }

  private generateRecommendations(lighthouseResults: LighthouseResults): string[] {
    const recommendations: string[] = [];
    const audits = lighthouseResults.audits;

    // Check performance score
    if (lighthouseResults.performance < this.config.thresholds.performance) {
      recommendations.push(
        `Performance score (${lighthouseResults.performance}) is below threshold (${this.config.thresholds.performance}). Focus on Core Web Vitals optimization.`
      );
    }

    // LCP recommendations
    const lcp = audits['largest-contentful-paint'];
    if (lcp && lcp.score < 0.9) {
      recommendations.push(
        'Improve Largest Contentful Paint: Optimize server response times, preload critical resources, and optimize images.'
      );
    }

    // FID recommendations
    const fid = audits['max-potential-fid'];
    if (fid && fid.score < 0.9) {
      recommendations.push(
        'Improve First Input Delay: Reduce JavaScript execution time, break up long tasks, and use web workers.'
      );
    }

    // CLS recommendations
    const cls = audits['cumulative-layout-shift'];
    if (cls && cls.score < 0.9) {
      recommendations.push(
        'Improve Cumulative Layout Shift: Set size attributes on images and videos, avoid inserting content above existing content.'
      );
    }

    // Image optimization
    if (audits['uses-optimized-images']?.score < 0.9) {
      recommendations.push(
        'Optimize images: Compress images, use responsive images, and implement lazy loading.'
      );
    }

    // JavaScript optimization
    if (audits['bootup-time']?.score < 0.9) {
      recommendations.push(
        'Reduce JavaScript execution time: Code-split, tree-shake, and defer non-critical JavaScript.'
      );
    }

    // Render-blocking resources
    if (audits['render-blocking-resources']?.score < 0.9) {
      recommendations.push(
        'Eliminate render-blocking resources: Inline critical CSS, defer non-critical CSS and JavaScript.'
      );
    }

    // Unused resources
    if (audits['unused-css-rules']?.score < 0.9) {
      recommendations.push(
        'Remove unused CSS: Audit and remove unused style rules to reduce CSS bundle size.'
      );
    }

    // Caching
    if (audits['uses-long-cache-ttl']?.score < 0.9) {
      recommendations.push(
        'Implement efficient caching: Set long cache TTL for static resources and use cache busting.'
      );
    }

    // HTTP/2
    if (audits['uses-http2']?.score < 1) {
      recommendations.push(
        'Enable HTTP/2 or HTTP/3: Upgrade to modern HTTP protocols for better performance.'
      );
    }

    return recommendations;
  }

  private getThrottlingConfig(): any {
    const throttling = this.config.lighthouseConfig.throttling;
    
    const configs: Record<string, any> = {
      '4G': {
        rttMs: 40,
        throughputKbps: 10 * 1024,
        requestLatencyMs: 0,
        downloadThroughputKbps: 10 * 1024,
        uploadThroughputKbps: 3 * 1024,
        cpuSlowdownMultiplier: 4
      },
      '3G': {
        rttMs: 150,
        throughputKbps: 1.6 * 1024,
        requestLatencyMs: 0,
        downloadThroughputKbps: 1.6 * 1024,
        uploadThroughputKbps: 750,
        cpuSlowdownMultiplier: 4
      },
      'none': undefined
    };

    return configs[throttling];
  }
}