import { validateUrl, validateConfig } from '../../src/utils/validators';
import { defaultConfig } from '../../src/config/defaults';

describe('Validators', () => {
  describe('validateUrl', () => {
    it('should validate correct HTTP URLs', () => {
      expect(validateUrl('http://example.com')).toBe(true);
      expect(validateUrl('https://example.com')).toBe(true);
    });

    it('should reject invalid URLs', () => {
      expect(validateUrl('not-a-url')).toBe(false);
      expect(validateUrl('ftp://example.com')).toBe(false);
      expect(validateUrl('')).toBe(false);
    });

    it('should handle URLs with paths', () => {
      expect(validateUrl('https://example.com/path/to/page')).toBe(true);
      expect(validateUrl('https://example.com:8080/api')).toBe(true);
    });
  });

  describe('validateConfig', () => {
    it('should validate default configuration', () => {
      const result = validateConfig(defaultConfig);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject invalid configuration', () => {
      const invalidConfig: any = {
        security: {
          enabled: 'yes', // Should be boolean
          scanDepth: 'invalid'
        }
      };
      
      const result = validateConfig(invalidConfig);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should validate threshold values', () => {
      const config: any = {
        ...defaultConfig,
        performance: {
          ...defaultConfig.performance,
          thresholds: {
            performance: 150, // Invalid: > 100
            accessibility: 80,
            bestPractices: 80,
            seo: 80
          }
        }
      };
      
      const result = validateConfig(config);
      expect(result.valid).toBe(false);
    });
  });
});