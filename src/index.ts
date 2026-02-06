#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import * as path from 'path';
import * as fs from 'fs/promises';
import { AnalysisEngine } from '../src/core/AnalysisEngine';
import { AnalysisTarget, AnalysisConfig } from '../src/types';
import { defaultConfig } from 'src/config/defaults';
import { validateUrl, validatePath } from '@utils/validators';

const program = new Command();

program
  .name('code-review')
  .description('Automated Code Review & Security Audit System')
  .version('1.0.0');

program
  .option('--url <url>', 'Website URL to analyze')
  .option('--repo <repository>', 'Git repository URL')
  .option('--path <directory>', 'Local directory path')
  .option('--security', 'Enable security scanning')
  .option('--performance', 'Enable performance analysis')
  .option('--seo', 'Enable SEO analysis')
  .option('--accessibility', 'Enable accessibility checking')
  .option('--code-quality', 'Enable code quality analysis')
  .option('--full-scan', 'Run all analysis modules')
  .option('--output <formats>', 'Output format (html,pdf,markdown,json,gama,pptx)', 'html,json')
  .option('--config <file>', 'Custom configuration file')
  .option('--output-dir <directory>', 'Output directory for reports', './reports')
  .option('--verbose', 'Detailed logging')
  .option('--quiet', 'Minimal output')
  .option('-i, --interactive', 'Interactive mode')
  .action(async (options) => {
    try {
      // Interactive mode
      if (options.interactive) {
        await runInteractiveMode();
        return;
      }

      // Validate input
      const target = await getAnalysisTarget(options);
      if (!target) {
        console.error(chalk.red('Error: Please specify a target using --url, --repo, or --path'));
        process.exit(1);
      }

      // Load configuration
      const config = await loadConfiguration(options);

      // Display banner
      displayBanner();

      // Run analysis
      const spinner = ora('Initializing analysis...').start();
      
      const engine = new AnalysisEngine(config);

      // Progress handler
      engine.on('progress', (progress) => {
        spinner.text = `${progress.message} (${progress.percentage}%)`;
      });

      const results = await engine.analyze(target);

      spinner.succeed(chalk.green('Analysis completed successfully!'));

      // Display summary
      displaySummary(results);

      // Display report locations
      displayReportLocations(config.reporting.outputDir, config.reporting.formats);

    } catch (error: any) {
      console.error(chalk.red(`\n✗ Error: ${error.message}`));
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

// Server mode
program
  .command('serve')
  .description('Start API server')
  .option('-p, --port <port>', 'Server port', '3000')
  .option('-h, --host <host>', 'Server host', 'localhost')
  .action(async (options) => {
    const { startServer } = await import('../api/server');
    await startServer(parseInt(options.port), options.host);
  });

// Config command
program
  .command('config')
  .description('Generate configuration file')
  .option('-o, --output <file>', 'Output file', 'code-review.config.json')
  .action(async (options) => {
    try {
      await fs.writeFile(
        options.output,
        JSON.stringify(defaultConfig, null, 2),
        'utf-8'
      );
      console.log(chalk.green(`✓ Configuration file created: ${options.output}`));
    } catch (error: any) {
      console.error(chalk.red(`Error creating config: ${error.message}`));
      process.exit(1);
    }
  });

// Helper functions
async function getAnalysisTarget(options: any): Promise<AnalysisTarget | null> {
  if (options.url) {
    if (!validateUrl(options.url)) {
      throw new Error('Invalid URL format');
    }
    return {
      type: 'url',
      value: options.url
    };
  }

  if (options.repo) {
    return {
      type: 'repository',
      value: options.repo
    };
  }

  if (options.path) {
    if (!await validatePath(options.path)) {
      throw new Error('Invalid or non-existent path');
    }
    return {
      type: 'local',
      value: path.resolve(options.path)
    };
  }

  return null;
}

async function loadConfiguration(options: any): Promise<AnalysisConfig> {
  let config = { ...defaultConfig };

  // Load custom config file if specified
  if (options.config) {
    try {
      const configFile = await fs.readFile(options.config, 'utf-8');
      const customConfig = JSON.parse(configFile);
      config = { ...config, ...customConfig };
    } catch (error: any) {
      throw new Error(`Failed to load config file: ${error.message}`);
    }
  }

  // Override with CLI options
  if (options.fullScan) {
    config.security.enabled = true;
    config.performance.enabled = true;
    config.codeQuality.enabled = true;
    config.seo.enabled = true;
    config.accessibility.enabled = true;
  } else {
    if (options.security !== undefined) config.security.enabled = options.security;
    if (options.performance !== undefined) config.performance.enabled = options.performance;
    if (options.codeQuality !== undefined) config.codeQuality.enabled = options.codeQuality;
    if (options.seo !== undefined) config.seo.enabled = options.seo;
    if (options.accessibility !== undefined) config.accessibility.enabled = options.accessibility;
  }

  // Set output formats
  if (options.output) {
    config.reporting.formats = options.output.split(',').map((f: string) => f.trim());
  }

  // Set output directory
  if (options.outputDir) {
    config.reporting.outputDir = options.outputDir;
  }

  return config;
}

async function runInteractiveMode(): Promise<void> {
  console.log(chalk.cyan.bold('\n🔍 Code Review Agent - Interactive Mode\n'));

  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'targetType',
      message: 'What would you like to analyze?',
      choices: [
        { name: '🌐 Website URL', value: 'url' },
        { name: '📦 Git Repository', value: 'repo' },
        { name: '📁 Local Directory', value: 'path' }
      ]
    },
    {
      type: 'input',
      name: 'targetValue',
      message: (answers: any) => {
        switch (answers.targetType) {
          case 'url': return 'Enter website URL:';
          case 'repo': return 'Enter repository URL:';
          case 'path': return 'Enter directory path:';
          default: return 'Enter target:';
        }
      },
      validate: async (input: string, answers: any) => {
        if (!input) return 'Please enter a value';
        if (answers.targetType === 'url' && !validateUrl(input)) {
          return 'Please enter a valid URL';
        }
        if (answers.targetType === 'path' && !await validatePath(input)) {
          return 'Path does not exist';
        }
        return true;
      }
    },
    {
      type: 'checkbox',
      name: 'modules',
      message: 'Select analysis modules:',
      choices: [
        { name: '🔒 Security Scan', value: 'security', checked: true },
        { name: '⚡ Performance Analysis', value: 'performance', checked: true },
        { name: '📝 Code Quality', value: 'codeQuality', checked: true },
        { name: '🔍 SEO Analysis', value: 'seo', checked: false },
        { name: '♿ Accessibility', value: 'accessibility', checked: false }
      ]
    },
    {
      type: 'checkbox',
      name: 'outputFormats',
      message: 'Select output formats:',
      choices: [
        { name: '📄 HTML Report', value: 'html', checked: true },
        { name: '📋 PDF Report', value: 'pdf', checked: false },
        { name: '📊 JSON Data', value: 'json', checked: true },
        { name: '📝 Markdown', value: 'markdown', checked: false },
        { name: '🎨 Gama Presentation', value: 'gama', checked: false },
        { name: '📊 PowerPoint', value: 'pptx', checked: false }
      ]
    }
  ]);

  // Build command
  const args = [
    `--${answers.targetType}`,
    answers.targetValue,
    ...answers.modules.map((m: string) => `--${m}`),
    '--output',
    answers.outputFormats.join(',')
  ];

  // Run with constructed options
  program.parse(['node', 'code-review', ...args]);
}

function displayBanner(): void {
  console.log(chalk.cyan.bold('\n╔══════════════════════════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║    Code Review & Security Audit System v1.0.0          ║'));
  console.log(chalk.cyan.bold('╚══════════════════════════════════════════════════════════╝\n'));
}

function displaySummary(results: any): void {
  console.log(chalk.bold('\n📊 Analysis Summary:\n'));
  
  // Overall score
  const scoreColor = results.overallScore >= 80 ? 'green' : 
                     results.overallScore >= 60 ? 'yellow' : 'red';
  console.log(chalk.bold('Overall Health Score: ') + chalk[scoreColor].bold(`${results.overallScore}/100`));
  
  // Individual scores
  console.log('\n' + chalk.bold('Component Scores:'));
  if (results.scores.security > 0) {
    console.log(`  🔒 Security:      ${formatScore(results.scores.security)}`);
  }
  if (results.scores.performance > 0) {
    console.log(`  ⚡ Performance:   ${formatScore(results.scores.performance)}`);
  }
  if (results.scores.codeQuality > 0) {
    console.log(`  📝 Code Quality:  ${formatScore(results.scores.codeQuality)}`);
  }
  if (results.scores.seo > 0) {
    console.log(`  🔍 SEO:           ${formatScore(results.scores.seo)}`);
  }
  if (results.scores.accessibility > 0) {
    console.log(`  ♿ Accessibility: ${formatScore(results.scores.accessibility)}`);
  }

  // Issue summary
  console.log('\n' + chalk.bold('Issues Found:'));
  console.log(`  ${chalk.red('●')} Critical: ${results.summary.criticalIssues}`);
  console.log(`  ${chalk.yellow('●')} High:     ${results.summary.highIssues}`);
  console.log(`  ${chalk.blue('●')} Medium:   ${results.summary.mediumIssues}`);
  console.log(`  ${chalk.gray('●')} Low:      ${results.summary.lowIssues}`);

  // Top recommendations
  if (results.recommendations && results.recommendations.length > 0) {
    console.log('\n' + chalk.bold('🎯 Top Recommendations:'));
    results.recommendations.slice(0, 5).forEach((rec: any, index: number) => {
      const priorityIcon = rec.priority === 'critical' ? '🔴' :
                          rec.priority === 'high' ? '🟡' : '🔵';
      console.log(`  ${priorityIcon} ${rec.title}`);
    });
  }

  console.log();
}

function formatScore(score: number): string {
  const color = score >= 80 ? 'green' : score >= 60 ? 'yellow' : 'red';
  return chalk[color](`${score}/100`);
}

function displayReportLocations(outputDir: string, formats: string[]): void {
  console.log(chalk.bold('\n📁 Reports Generated:\n'));
  formats.forEach(format => {
    const fileName = `code-review-report.${format}`;
    const filePath = path.join(outputDir, fileName);
    console.log(`  ${getFormatIcon(format)} ${filePath}`);
  });
  console.log();
}

function getFormatIcon(format: string): string {
  const icons: Record<string, string> = {
    html: '🌐',
    pdf: '📄',
    json: '📊',
    markdown: '📝',
    gama: '🎨',
    pptx: '📊'
  };
  return icons[format] || '📄';
}

// Parse command line arguments
program.parse(process.argv);

// Show help if no arguments provided
if (process.argv.length === 2) {
  program.help();
}