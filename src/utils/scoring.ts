import { AnalysisConfig, Recommendation } from '../types';

export function calculateOverallScore(scores: any, config: AnalysisConfig): number {
  let totalWeight = 0;
  let weightedScore = 0;

  if (config.security.enabled && scores.security > 0) {
    weightedScore += scores.security * 0.35;
    totalWeight += 0.35;
  }

  if (config.performance.enabled && scores.performance > 0) {
    weightedScore += scores.performance * 0.25;
    totalWeight += 0.25;
  }

  if (config.codeQuality.enabled && scores.codeQuality > 0) {
    weightedScore += scores.codeQuality * 0.25;
    totalWeight += 0.25;
  }

  if (config.seo.enabled && scores.seo > 0) {
    weightedScore += scores.seo * 0.075;
    totalWeight += 0.075;
  }

  if (config.accessibility.enabled && scores.accessibility > 0) {
    weightedScore += scores.accessibility * 0.075;
    totalWeight += 0.075;
  }

  return totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 0;
}

export function generateRecommendations(
  security: any,
  performance: any,
  codeQuality: any,
  seo: any,
  accessibility: any
): Recommendation[] {
  const recommendations: Recommendation[] = [];

  // Security recommendations
  if (security && security.vulnerabilities) {
    security.vulnerabilities
      .filter((v: any) => v.severity === 'critical' || v.severity === 'high')
      .slice(0, 5)
      .forEach((vuln: any) => {
        recommendations.push({
          id: vuln.id,
          category: 'security',
          priority: vuln.severity === 'critical' ? 'critical' : 'high',
          title: vuln.title,
          description: vuln.description,
          impact: 'High security risk that could lead to data breach or system compromise',
          effort: 'medium',
          steps: [vuln.remediation],
          resources: vuln.references,
          estimatedTime: vuln.severity === 'critical' ? '1-2 hours' : '2-4 hours'
        });
      });
  }

  // Performance recommendations
  if (performance && performance.recommendations) {
    performance.recommendations.slice(0, 3).forEach((rec: string) => {
      recommendations.push({
        id: `perf-${Date.now()}`,
        category: 'performance',
        priority: 'medium',
        title: rec,
        description: rec,
        impact: 'Improves user experience and search engine rankings',
        effort: 'medium',
        steps: [rec],
        resources: ['https://web.dev/performance'],
        estimatedTime: '4-8 hours'
      });
    });
  }

  // Sort by priority
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  recommendations.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  return recommendations;
}
