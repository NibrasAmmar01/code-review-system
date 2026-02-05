import * as fs from 'fs/promises';
import Joi from 'joi';
import { AnalysisConfig } from '../types';

export function validateUrl(url: string): boolean {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
  } catch {
    return false;
  }
}

export async function validatePath(filePath: string): Promise<boolean> {
  try {
    const stats = await fs.stat(filePath);
    return stats.isDirectory() || stats.isFile();
  } catch {
    return false;
  }
}

export function validateConfig(config: AnalysisConfig): { valid: boolean; errors: string[] } {
  const schema = Joi.object({
    security: Joi.object({
      enabled: Joi.boolean().required(),
      scanDepth: Joi.string().valid('shallow', 'medium', 'deep').required(),
      excludePatterns: Joi.array().items(Joi.string()).required(),
      sensitiveDataPatterns: Joi.array().items(Joi.string()).required(),
      osint: Joi.object({
        enabled: Joi.boolean().required(),
        checkDependencies: Joi.boolean().required(),
        checkGitHistory: Joi.boolean().optional()
      }).required(),
      vulnerabilityThresholds: Joi.object({
        critical: Joi.number().min(0).required(),
        high: Joi.number().min(0).required(),
        medium: Joi.number().min(0).required(),
        low: Joi.number().min(0).required()
      }).required()
    }).required(),
    performance: Joi.object({
      enabled: Joi.boolean().required(),
      lighthouseConfig: Joi.object({
        formFactor: Joi.string().valid('mobile', 'desktop').required(),
        throttling: Joi.string().valid('4G', '3G', 'none').required(),
        onlyCategories: Joi.array().items(Joi.string()).optional()
      }).required(),
      thresholds: Joi.object({
        performance: Joi.number().min(0).max(100).required(),
        accessibility: Joi.number().min(0).max(100).required(),
        bestPractices: Joi.number().min(0).max(100).required(),
        seo: Joi.number().min(0).max(100).required()
      }).required()
    }).required(),
    codeQuality: Joi.object({
      enabled: Joi.boolean().required(),
      languages: Joi.array().items(Joi.string()).required(),
      complexityThreshold: Joi.number().min(1).required(),
      duplicateThreshold: Joi.number().min(0).required(),
      checkTests: Joi.boolean().required(),
      checkDocumentation: Joi.boolean().required()
    }).required(),
    seo: Joi.object({
      enabled: Joi.boolean().required(),
      checkMobileFriendly: Joi.boolean().required(),
      checkStructuredData: Joi.boolean().required(),
      checkSitemap: Joi.boolean().required(),
      checkRobotsTxt: Joi.boolean().required()
    }).required(),
    accessibility: Joi.object({
      enabled: Joi.boolean().required(),
      wcagLevel: Joi.string().valid('A', 'AA', 'AAA').required(),
      checkARIA: Joi.boolean().required(),
      checkContrast: Joi.boolean().required(),
      checkKeyboardNav: Joi.boolean().required()
    }).required(),
    reporting: Joi.object({
      formats: Joi.array().items(Joi.string().valid('html', 'pdf', 'markdown', 'json', 'gama', 'pptx')).required(),
      outputDir: Joi.string().required(),
      includeMetrics: Joi.boolean().required(),
      executiveSummary: Joi.boolean().required(),
      detailedFindings: Joi.boolean().required()
    }).required(),
    notifications: Joi.object({
      slack: Joi.object({
        enabled: Joi.boolean().required(),
        webhook: Joi.string().uri().when('enabled', { is: true, then: Joi.required() }),
        channel: Joi.string().optional()
      }).optional(),
      email: Joi.object({
        enabled: Joi.boolean().required(),
        recipients: Joi.array().items(Joi.string().email()).when('enabled', { is: true, then: Joi.required() }),
        smtp: Joi.object({
          host: Joi.string().required(),
          port: Joi.number().required(),
          secure: Joi.boolean().required(),
          auth: Joi.object({
            user: Joi.string().required(),
            pass: Joi.string().required()
          }).required()
        }).optional()
      }).optional(),
      webhook: Joi.object({
        enabled: Joi.boolean().required(),
        url: Joi.string().uri().when('enabled', { is: true, then: Joi.required() }),
        headers: Joi.object().pattern(Joi.string(), Joi.string()).optional()
      }).optional()
    }).optional()
  });

  const { error } = schema.validate(config, { abortEarly: false });

  if (error) {
    return {
      valid: false,
      errors: error.details.map(d => d.message)
    };
  }

  return { valid: true, errors: [] };
}

export function sanitizeInput(input: string): string {
  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .trim();
}

export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function isValidGitRepo(url: string): boolean {
  const gitRegex = /^(https?:\/\/)?([\w.-]+)(\/[\w.-]+)*\.git$/;
  return gitRegex.test(url) || url.includes('github.com') || url.includes('gitlab.com') || url.includes('bitbucket.org');
}