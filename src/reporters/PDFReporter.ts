import * as fs from 'fs';
import * as path from 'path';
import PDFDocument from 'pdfkit';
import { AnalysisResults, ReportingConfig, Logger } from '../types';

export class PDFReporter {
  constructor(private config: ReportingConfig, private logger: Logger) {}

  public async generate(results: AnalysisResults): Promise<void> {
    const filePath = path.join(this.config.outputDir, 'code-review-report.pdf');
    const doc = new PDFDocument();
    const stream = fs.createWriteStream(filePath);

    doc.pipe(stream);

    doc.fontSize(24).text('Code Review & Security Audit Report', { align: 'center' });
    doc.moveDown();
    doc.fontSize(48).text(\`\${results.overallScore}/100\`, { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(\`Target: \${results.target.value}\`);
    doc.text(\`Date: \${results.timestamp}\`);

    doc.end();

    return new Promise((resolve) => {
      stream.on('finish', resolve);
    });
  }
}
