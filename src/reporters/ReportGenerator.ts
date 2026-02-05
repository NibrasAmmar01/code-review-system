import * as fs from 'fs/promises';
import * as path from 'path';
import Handlebars from 'handlebars';
import { AnalysisResults, ReportingConfig, Logger } from '../types';
import { ensureDirectory, writeJsonFile } from '../utils/fileUtils';
import { HTMLReporter } from './HTMLReporter';
import { PDFReporter } from './PDFReporter';
import { MarkdownReporter } from './MarkdownReporter';

export class ReportGenerator {
  constructor(
    private config: ReportingConfig,
    private logger: Logger
  ) {}

  public async generate(results: AnalysisResults): Promise<void> {
    this.logger.info('Generating reports');

    await ensureDirectory(this.config.outputDir);

    for (const format of this.config.formats) {
      try {
        switch (format) {
          case 'html':
            await new HTMLReporter(this.config, this.logger).generate(results);
            break;
          case 'pdf':
            await new PDFReporter(this.config, this.logger).generate(results);
            break;
          case 'markdown':
            await new MarkdownReporter(this.config, this.logger).generate(results);
            break;
          case 'json':
            await this.generateJSON(results);
            break;
          case 'gama':
            await this.generateGama(results);
            break;
          case 'pptx':
            await this.generatePowerPoint(results);
            break;
        }
        this.logger.info(`Generated ${format} report`);
      } catch (error) {
        this.logger.error(`Failed to generate ${format} report:`, error);
      }
    }
  }

  private async generateJSON(results: AnalysisResults): Promise<void> {
    const filePath = path.join(this.config.outputDir, 'code-review-report.json');
    await writeJsonFile(filePath, results);
  }

  private async generateGama(results: AnalysisResults): Promise<void> {
    this.logger.info('Gama presentation generation not yet implemented');
  }

  private async generatePowerPoint(results: AnalysisResults): Promise<void> {
    this.logger.info('PowerPoint generation not yet implemented');
  }
}
