import * as fs from 'fs/promises';
import * as path from 'path';
import Handlebars from 'handlebars';
import { AnalysisResults, ReportingConfig, Logger } from '../types';

export class HTMLReporter {
  constructor(private config: ReportingConfig, private logger: Logger) {}

  public async generate(results: AnalysisResults): Promise<void> {
    const template = await this.loadTemplate();
    const html = template(results);
    const filePath = path.join(this.config.outputDir, 'code-review-report.html');
    await fs.writeFile(filePath, html, 'utf-8');
  }

  private async loadTemplate(): Promise<HandlebarsTemplateDelegate> {
    const templatePath = path.join(__dirname, '../../templates/report.hbs');
    try {
      const templateContent = await fs.readFile(templatePath, 'utf-8');
      return Handlebars.compile(templateContent);
    } catch {
      return Handlebars.compile(this.getDefaultTemplate());
    }
  }

  private getDefaultTemplate(): string {
    return \`
<!DOCTYPE html>
<html>
<head>
  <title>Code Review Report</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
    h1 { color: #333; }
    .score { font-size: 48px; font-weight: bold; }
    .good { color: #4CAF50; }
    .warning { color: #FF9800; }
    .error { color: #F44336; }
  </style>
</head>
<body>
  <h1>Code Review & Security Audit Report</h1>
  <div class="score {{#if (gt overallScore 80)}}good{{else if (gt overallScore 60)}}warning{{else}}error{{/if}}">
    {{overallScore}}/100
  </div>
  <h2>Analysis Summary</h2>
  <p>Target: {{target.value}}</p>
  <p>Date: {{timestamp}}</p>
</body>
</html>
    \`;
  }
}
