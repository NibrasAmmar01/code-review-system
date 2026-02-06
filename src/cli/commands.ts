import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { AnalysisEngine } from '../core/AnalysisEngine';
import { AnalysisTarget, AnalysisConfig } from '../types';
import { defaultConfig } from '../config/defaults';
import { Logger } from '../utils/Logger';
import * as fs from 'fs/promises';
import * as path from 'path';

const logger = new Logger();

/**
 * Scan command - main analysis command
 */
export function createScanCommand(): Command {
  const command = new Command('scan');
  
  command
    .description('Run code review and security audit')
    .argument('[target]', 'Target to scan (URL, repository, or path)')
    .option('-u, --url <url>', 'Website URL to analyze')
    .option('-r, --repo <repository>', 'Git repository URL')
    .option('-p, --path <directory>', 'Local directory path')
    .option('--security', 'Enable security scanning', true)
    .option('--performance', 'Enable performance analysis')
    .option('--seo', 'Enable SEO analysis')
    .option('--accessibility', 'Enable accessibility checking')
    .option('--code-quality', 'Enable code quality analysis')
    .option('--full-scan', 'Run all analysis modules')
    .option('-o, --output <formats>', 'Output format (html,pdf,json,markdown,gama)', 'html,json')
    .option('--output-dir <directory>', 'Output directory for reports', './reports')
    .option('-c, --config <file>', 'Custom configuration file')
    .option('--verbose', 'Verbose logging')
    .action(async (target, options) => {
      try {
        await runScan(target, options);
      } catch (error: any) {
        console.error(chalk.red(`\n✗ Error: ${error.message}`));
        if (options.verbose) {
          console.error(error.stack);
        }
        process.exit(1);
      }
    });

  return command;
}

/**
 * Serve command - start API server
 */
export function createServeCommand(): Command {
  const command = new Command('serve');
  
  command
    .description('Start API server')
    .option('-p, --port <port>', 'Server port', '3000')
    .option('-h, --host <host>', 'Server host', 'localhost')
    .option('--no-auth', 'Disable authentication')
    .action(async (options) => {
      try {
        const { startServer } = await import('../api/server');
        console.log(chalk.cyan('\n🚀 Starting Code Review API Server...\n'));
        await startServer(parseInt(options.port), options.host);
      } catch (error: any) {
        console.error(chalk.red(`\n✗ Failed to start server: ${error.message}`));
        process.exit(1);
      }
    });

  return command;
}

/**
 * Config command - generate configuration file
 */
export function createConfigCommand(): Command {
  const command = new Command('config');
  
  command
    .description('Generate configuration file')
    .option('-o, --output <file>', 'Output file', 'code-review.config.json')
    .option('--full', 'Include all options with comments')
    .action(async (options) => {
      try {
        const configContent = options.full 
          ? generateFullConfig() 
          : JSON.stringify(defaultConfig, null, 2);

        await fs.writeFile(options.output, configContent, 'utf-8');
        console.log(chalk.green(`\n✓ Configuration file created: ${options.output}\n`));
      } catch (error: any) {
        console.error(chalk.red(`\n✗ Error creating config: ${error.message}\n`));
        process.exit(1);
      }
    });

  return command;
}

/**
 * Report command - generate report from existing results
 */
export function createReportCommand(): Command {
  const command = new Command('report');
  
  command
    .description('Generate report from scan results')
    .argument('<results-file>', 'Path to JSON results file')
    .option('-o, --output <formats>', 'Output format (html,pdf,markdown)', 'html')
    .option('--output-dir <directory>', 'Output directory', './reports')
    .action(async (resultsFile, options) => {
      try {
        console.log(chalk.cyan('\n📊 Generating report...\n'));
        
        const resultsContent = await fs.readFile(resultsFile, 'utf-8');
        const results = JSON.parse(resultsContent);
        
        const { ReportGenerator } = await import('../reporters/ReportGenerator');
        const reportConfig = {
          ...defaultConfig.reporting,
          formats: options.output.split(','),
          outputDir: options.outputDir
        };
        
        const generator = new ReportGenerator(reportConfig, logger);
        await generator.generate(results);
        
        console.log(chalk.green(`\n✓ Report generated successfully!\n`));
        console.log(chalk.gray(`Output directory: ${options.outputDir}\n`));
      } catch (error: any) {
        console.error(chalk.red(`\n✗ Error generating report: ${error.message}\n`));
        process.exit(1);
      }
    });

  return command;
}

/**
 * List command - list available analyzers and reporters
 */
export function createListCommand(): Command {
  const command = new Command('list');
  
  command
    .description('List available analyzers and reporters')
    .option('--analyzers', 'List available analyzers')
    .option('--reporters', 'List available report formats')
    .action((options) => {
      if (options.analyzers || (!options.analyzers && !options.reporters)) {
        console.log(chalk.cyan('\n📋 Available Analyzers:\n'));
        console.log('  🔒 security      - Vulnerability scanning and security audit');
        console.log('  ⚡ performance   - Lighthouse performance analysis');
        console.log('  📝 code-quality  - Code smell detection and quality metrics');
        console.log('  🔍 seo           - SEO optimization analysis');
        console.log('  ♿ accessibility - WCAG compliance checking');
        console.log('');
      }
      
      if (options.reporters || (!options.analyzers && !options.reporters)) {
        console.log(chalk.cyan('📊 Available Report Formats:\n'));
        console.log('  📄 html         - Interactive HTML report');
        console.log('  📋 pdf          - Printable PDF document');
        console.log('  📝 markdown     - Markdown documentation');
        console.log('  📊 json         - Machine-readable JSON data');
        console.log('  🎨 gama         - Gama presentation (coming soon)');
        console.log('  📊 pptx         - PowerPoint presentation (coming soon)');
        console.log('');
      }
    });

  return command;
}

/**
 * Validate command - validate configuration or target
 */
export function createValidateCommand(): Command {
  const command = new Command('validate');
  
  command
    .description('Validate configuration or target')
    .argument('[file]', 'Configuration file to validate')
    .action(async (file) => {
      try {
        if (!file) {
          file = 'code-review.config.json';
        }
        
        const configContent = await fs.readFile(file, 'utf-8');
        const config = JSON.parse(configContent);
        
        const { validateConfig } = await import('../utils/validators');
        const validation = validateConfig(config);
        
        if (validation.valid) {
          console.log(chalk.green('\n✓ Configuration is valid!\n'));
        } else {
          console.log(chalk.red('\n✗ Configuration has errors:\n'));
          validation.errors.forEach(error => {
            console.log(chalk.red(`  • ${error}`));
          });
          console.log('');
          process.exit(1);
        }
      } catch (error: any) {
        console.error(chalk.red(`\n✗ Error validating config: ${error.message}\n`));
        process.exit(1);
      }
    });

  return command;
}

/**
 * Init command - initialize project with config
 */
export function createInitCommand(): Command {
  const command = new Command('init');
  
  command
    .description('Initialize project with configuration')
    .option('--force', 'Overwrite existing configuration')
    .action(async (options) => {
      try {
        const configPath = 'code-review.config.json';
        const gitignorePath = '.gitignore';
        
        // Check if config exists
        const configExists = await fs.access(configPath).then(() => true).catch(() => false);
        
        if (configExists && !options.force) {
          console.log(chalk.yellow('\n⚠ Configuration file already exists. Use --force to overwrite.\n'));
          return;
        }
        
        // Create config
        await fs.writeFile(configPath, JSON.stringify(defaultConfig, null, 2), 'utf-8');
        console.log(chalk.green(`✓ Created ${configPath}`));
        
        // Update .gitignore
        const gitignoreContent = '\n# Code Review Reports\nreports/\nlogs/\n*.log\n';
        
        try {
          const existingGitignore = await fs.readFile(gitignorePath, 'utf-8');
          if (!existingGitignore.includes('reports/')) {
            await fs.appendFile(gitignorePath, gitignoreContent);
            console.log(chalk.green(`✓ Updated ${gitignorePath}`));
          }
        } catch {
          await fs.writeFile(gitignorePath, gitignoreContent, 'utf-8');
          console.log(chalk.green(`✓ Created ${gitignorePath}`));
        }
        
        console.log(chalk.cyan('\n🎉 Project initialized successfully!\n'));
        console.log(chalk.gray('Next steps:'));
        console.log(chalk.gray('  1. Edit code-review.config.json to customize settings'));
        console.log(chalk.gray('  2. Run: code-review scan --full-scan\n'));
      } catch (error: any) {
        console.error(chalk.red(`\n✗ Error initializing project: ${error.message}\n`));
        process.exit(1);
      }
    });

  return command;
}

// Helper functions

async function runScan(target: string | undefined, options: any): Promise<void> {
  const spinner = ora('Initializing analysis...').start();
  
  try {
    // Determine target
    const analysisTarget = getAnalysisTarget(target, options);
    if (!analysisTarget) {
      spinner.fail('No target specified');
      console.log(chalk.yellow('\nPlease specify a target using:'));
      console.log('  --url <url>        for websites');
      console.log('  --repo <repo>      for repositories');
      console.log('  --path <path>      for local directories\n');
      process.exit(1);
    }
    
    // Load configuration
    const config = await loadConfig(options);
    
    // Create engine
    const engine = new AnalysisEngine(config);
    
    // Progress handler
    engine.on('progress', (progress) => {
      spinner.text = `${progress.message} (${progress.percentage}%)`;
    });
    
    // Run analysis
    const results = await engine.analyze(analysisTarget);
    
    spinner.succeed(chalk.green('Analysis completed successfully!'));
    
    // Display summary
    displayResults(results);
    
  } catch (error: any) {
    spinner.fail(chalk.red('Analysis failed'));
    throw error;
  }
}

function getAnalysisTarget(target: string | undefined, options: any): AnalysisTarget | null {
  if (options.url) {
    return { type: 'url', value: options.url };
  }
  
  if (options.repo) {
    return { type: 'repository', value: options.repo };
  }
  
  if (options.path) {
    return { type: 'local', value: path.resolve(options.path) };
  }
  
  if (target) {
    if (target.startsWith('http://') || target.startsWith('https://')) {
      return { type: 'url', value: target };
    } else if (target.includes('github.com') || target.includes('gitlab.com')) {
      return { type: 'repository', value: target };
    } else {
      return { type: 'local', value: path.resolve(target) };
    }
  }
  
  return null;
}

async function loadConfig(options: any): Promise<AnalysisConfig> {
  let config = { ...defaultConfig };
  
  // Load custom config if specified
  if (options.config) {
    const configContent = await fs.readFile(options.config, 'utf-8');
    const customConfig = JSON.parse(configContent);
    config = { ...config, ...customConfig };
  }
  
  // Apply CLI options
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
  
  // Set output options
  if (options.output) {
    config.reporting.formats = options.output.split(',').map((f: string) => f.trim());
  }
  
  if (options.outputDir) {
    config.reporting.outputDir = options.outputDir;
  }
  
  return config;
}

function displayResults(results: any): void {
  console.log(chalk.bold('\n📊 Analysis Summary:\n'));
  
  // Overall score
  const scoreColor = results.overallScore >= 80 ? 'green' : 
                     results.overallScore >= 60 ? 'yellow' : 'red';
  console.log(chalk.bold('Overall Health Score: ') + chalk[scoreColor].bold(`${results.overallScore}/100\n`));
  
  // Component scores
  console.log(chalk.bold('Component Scores:'));
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
  
  // Issues
  console.log(chalk.bold('\nIssues Found:'));
  console.log(`  ${chalk.red('●')} Critical: ${results.summary.criticalIssues}`);
  console.log(`  ${chalk.yellow('●')} High:     ${results.summary.highIssues}`);
  console.log(`  ${chalk.blue('●')} Medium:   ${results.summary.mediumIssues}`);
  console.log(`  ${chalk.gray('●')} Low:      ${results.summary.lowIssues}`);
  
  // Top recommendations
  if (results.recommendations && results.recommendations.length > 0) {
    console.log(chalk.bold('\n🎯 Top Recommendations:'));
    results.recommendations.slice(0, 5).forEach((rec: any) => {
      const icon = rec.priority === 'critical' ? '🔴' : 
                   rec.priority === 'high' ? '🟡' : '🔵';
      console.log(`  ${icon} ${rec.title}`);
    });
  }
  
  console.log('');
}

function formatScore(score: number): string {
  const color = score >= 80 ? 'green' : score >= 60 ? 'yellow' : 'red';
  return chalk[color](`${score}/100`);
}

function generateFullConfig(): string {
  return `{
  // Security Configuration
  "security": ${JSON.stringify(defaultConfig.security, null, 2)},
  
  // Performance Configuration
  "performance": ${JSON.stringify(defaultConfig.performance, null, 2)},
  
  // Code Quality Configuration
  "codeQuality": ${JSON.stringify(defaultConfig.codeQuality, null, 2)},
  
  // SEO Configuration
  "seo": ${JSON.stringify(defaultConfig.seo, null, 2)},
  
  // Accessibility Configuration
  "accessibility": ${JSON.stringify(defaultConfig.accessibility, null, 2)},
  
  // Reporting Configuration
  "reporting": ${JSON.stringify(defaultConfig.reporting, null, 2)}
}`;
}