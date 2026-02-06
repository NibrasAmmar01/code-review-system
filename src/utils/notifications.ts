import axios from 'axios';
import { AnalysisResults } from '../types';
import { Logger } from './Logger';

const logger = new Logger();

export interface SlackNotification {
  webhook: string;
  channel?: string;
  username?: string;
  iconEmoji?: string;
}

export interface EmailNotification {
  recipients: string[];
  subject: string;
  smtp?: {
    host: string;
    port: number;
    secure: boolean;
    auth: {
      user: string;
      pass: string;
    };
  };
}

export interface WebhookNotification {
  url: string;
  headers?: Record<string, string>;
  method?: 'POST' | 'PUT';
}

/**
 * Send Slack notification
 */
export async function sendSlackNotification(
  config: SlackNotification,
  results: AnalysisResults
): Promise<void> {
  try {
    const color = results.overallScore >= 80 ? 'good' : 
                  results.overallScore >= 60 ? 'warning' : 'danger';

    const message = {
      channel: config.channel,
      username: config.username || 'Code Review Bot',
      icon_emoji: config.iconEmoji || ':robot_face:',
      attachments: [
        {
          color,
          title: 'Code Review Completed',
          text: `Analysis finished for ${results.target.value}`,
          fields: [
            {
              title: 'Overall Score',
              value: `${results.overallScore}/100`,
              short: true
            },
            {
              title: 'Critical Issues',
              value: results.summary.criticalIssues.toString(),
              short: true
            },
            {
              title: 'Security',
              value: `${results.scores.security}/100`,
              short: true
            },
            {
              title: 'Performance',
              value: `${results.scores.performance}/100`,
              short: true
            }
          ],
          footer: 'Code Review Agent',
          ts: Math.floor(results.timestamp.getTime() / 1000)
        }
      ]
    };

    await axios.post(config.webhook, message);
    logger.info('Slack notification sent successfully');
  } catch (error: any) {
    logger.error('Failed to send Slack notification:', error.message);
    throw error;
  }
}

/**
 * Send email notification
 */
export async function sendEmailNotification(
  config: EmailNotification,
  results: AnalysisResults
): Promise<void> {
  try {
    // Note: In production, use nodemailer or similar
    const emailBody = generateEmailBody(results);

    logger.info(`Email notification prepared for ${config.recipients.join(', ')}`);
    logger.info('Email body:', emailBody);

    // Placeholder for actual email sending
    // const nodemailer = require('nodemailer');
    // const transporter = nodemailer.createTransporter(config.smtp);
    // await transporter.sendMail({
    //   from: config.smtp.auth.user,
    //   to: config.recipients.join(','),
    //   subject: config.subject,
    //   html: emailBody
    // });

  } catch (error: any) {
    logger.error('Failed to send email notification:', error.message);
    throw error;
  }
}

/**
 * Send webhook notification
 */
export async function sendWebhookNotification(
  config: WebhookNotification,
  results: AnalysisResults
): Promise<void> {
  try {
    const payload = {
      event: 'scan.completed',
      timestamp: results.timestamp.toISOString(),
      data: {
        target: results.target,
        overallScore: results.overallScore,
        scores: results.scores,
        summary: results.summary,
        recommendations: results.recommendations.slice(0, 5)
      }
    };

    await axios({
      method: config.method || 'POST',
      url: config.url,
      data: payload,
      headers: config.headers || {},
      timeout: 10000
    });

    logger.info(`Webhook notification sent to ${config.url}`);
  } catch (error: any) {
    logger.error('Failed to send webhook notification:', error.message);
    throw error;
  }
}

/**
 * Send notification based on severity
 */
export async function sendSeverityBasedNotification(
  results: AnalysisResults,
  config: {
    slack?: SlackNotification;
    email?: EmailNotification;
    webhook?: WebhookNotification;
  }
): Promise<void> {
  // Only send notifications if there are critical issues or low scores
  const shouldNotify = 
    results.summary.criticalIssues > 0 ||
    results.overallScore < 70 ||
    results.scores.security < 70;

  if (!shouldNotify) {
    logger.info('No notification sent - no critical issues found');
    return;
  }

  const notifications: Promise<void>[] = [];

  if (config.slack) {
    notifications.push(sendSlackNotification(config.slack, results));
  }

  if (config.email) {
    notifications.push(sendEmailNotification(config.email, results));
  }

  if (config.webhook) {
    notifications.push(sendWebhookNotification(config.webhook, results));
  }

  await Promise.allSettled(notifications);
}

/**
 * Generate email body HTML
 */
function generateEmailBody(results: AnalysisResults): string {
  const scoreColor = results.overallScore >= 80 ? '#4CAF50' : 
                     results.overallScore >= 60 ? '#FF9800' : '#F44336';

  return `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #2196F3; color: white; padding: 20px; text-align: center; }
    .score { font-size: 48px; font-weight: bold; color: ${scoreColor}; text-align: center; margin: 20px 0; }
    .section { margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }
    .metric { display: flex; justify-content: space-between; margin: 10px 0; }
    .metric-label { font-weight: bold; }
    .metric-value { color: ${scoreColor}; }
    .footer { text-align: center; color: #666; margin-top: 30px; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Code Review Report</h1>
      <p>${results.target.value}</p>
    </div>
    
    <div class="score">${results.overallScore}/100</div>
    
    <div class="section">
      <h2>Component Scores</h2>
      <div class="metric">
        <span class="metric-label">🔒 Security:</span>
        <span class="metric-value">${results.scores.security}/100</span>
      </div>
      <div class="metric">
        <span class="metric-label">⚡ Performance:</span>
        <span class="metric-value">${results.scores.performance}/100</span>
      </div>
      <div class="metric">
        <span class="metric-label">📝 Code Quality:</span>
        <span class="metric-value">${results.scores.codeQuality}/100</span>
      </div>
      <div class="metric">
        <span class="metric-label">🔍 SEO:</span>
        <span class="metric-value">${results.scores.seo}/100</span>
      </div>
      <div class="metric">
        <span class="metric-label">♿ Accessibility:</span>
        <span class="metric-value">${results.scores.accessibility}/100</span>
      </div>
    </div>
    
    <div class="section">
      <h2>Issues Summary</h2>
      <div class="metric">
        <span class="metric-label" style="color: #F44336;">● Critical:</span>
        <span>${results.summary.criticalIssues}</span>
      </div>
      <div class="metric">
        <span class="metric-label" style="color: #FF9800;">● High:</span>
        <span>${results.summary.highIssues}</span>
      </div>
      <div class="metric">
        <span class="metric-label" style="color: #2196F3;">● Medium:</span>
        <span>${results.summary.mediumIssues}</span>
      </div>
      <div class="metric">
        <span class="metric-label" style="color: #9E9E9E;">● Low:</span>
        <span>${results.summary.lowIssues}</span>
      </div>
    </div>
    
    <div class="section">
      <h2>Top Recommendations</h2>
      <ol>
        ${results.recommendations.slice(0, 5).map(rec => `
          <li><strong>${rec.title}</strong><br>${rec.description}</li>
        `).join('')}
      </ol>
    </div>
    
    <div class="footer">
      <p>Generated by Code Review Agent on ${results.timestamp.toLocaleString()}</p>
    </div>
  </div>
</body>
</html>
  `.trim();
}

/**
 * Format notification message
 */
export function formatNotificationMessage(results: AnalysisResults): string {
  return `
Code Review Completed

Target: ${results.target.value}
Overall Score: ${results.overallScore}/100

Scores:
- Security: ${results.scores.security}/100
- Performance: ${results.scores.performance}/100
- Code Quality: ${results.scores.codeQuality}/100
- SEO: ${results.scores.seo}/100
- Accessibility: ${results.scores.accessibility}/100

Issues:
- Critical: ${results.summary.criticalIssues}
- High: ${results.summary.highIssues}
- Medium: ${results.summary.mediumIssues}
- Low: ${results.summary.lowIssues}

Top Recommendations:
${results.recommendations.slice(0, 3).map((rec, i) => `${i + 1}. ${rec.title}`).join('\n')}
  `.trim();
}