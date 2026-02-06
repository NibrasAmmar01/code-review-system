import { EventEmitter } from 'events';
import { AnalysisEngine } from './AnalysisEngine';
import { AnalysisTarget, AnalysisConfig, AnalysisResults } from '../types';
import { Logger } from '../utils/Logger';

interface ScheduledTask {
  id: string;
  name: string;
  target: AnalysisTarget;
  config: AnalysisConfig;
  schedule: string; // Cron-like schedule
  enabled: boolean;
  lastRun?: Date;
  nextRun?: Date;
  lastResult?: AnalysisResults;
  runCount: number;
}

export class Scheduler extends EventEmitter {
  private tasks: Map<string, ScheduledTask> = new Map();
  private intervals: Map<string, NodeJS.Timeout> = new Map();
  private logger: Logger;
  private running: boolean = false;

  constructor() {
    super();
    this.logger = new Logger();
  }

  /**
   * Add a scheduled task
   */
  public addTask(
    id: string,
    name: string,
    target: AnalysisTarget,
    config: AnalysisConfig,
    schedule: string
  ): void {
    const task: ScheduledTask = {
      id,
      name,
      target,
      config,
      schedule,
      enabled: true,
      runCount: 0,
      nextRun: this.calculateNextRun(schedule)
    };

    this.tasks.set(id, task);
    this.logger.info(`Task ${id} scheduled: ${name}`);
    
    if (this.running) {
      this.scheduleTask(task);
    }

    this.emit('task:added', task);
  }

  /**
   * Remove a scheduled task
   */
  public removeTask(id: string): boolean {
    const task = this.tasks.get(id);
    if (!task) return false;

    this.unscheduleTask(id);
    this.tasks.delete(id);
    this.logger.info(`Task ${id} removed`);
    this.emit('task:removed', { id });

    return true;
  }

  /**
   * Enable a task
   */
  public enableTask(id: string): boolean {
    const task = this.tasks.get(id);
    if (!task) return false;

    task.enabled = true;
    if (this.running) {
      this.scheduleTask(task);
    }

    this.emit('task:enabled', task);
    return true;
  }

  /**
   * Disable a task
   */
  public disableTask(id: string): boolean {
    const task = this.tasks.get(id);
    if (!task) return false;

    task.enabled = false;
    this.unscheduleTask(id);
    this.emit('task:disabled', task);

    return true;
  }

  /**
   * Run a task immediately
   */
  public async runTask(id: string): Promise<AnalysisResults> {
    const task = this.tasks.get(id);
    if (!task) {
      throw new Error(`Task ${id} not found`);
    }

    this.logger.info(`Running task ${id} manually`);
    return await this.executeTask(task);
  }

  /**
   * Start the scheduler
   */
  public start(): void {
    if (this.running) {
      this.logger.warn('Scheduler already running');
      return;
    }

    this.running = true;
    this.logger.info('Scheduler started');

    // Schedule all enabled tasks
    for (const task of this.tasks.values()) {
      if (task.enabled) {
        this.scheduleTask(task);
      }
    }

    this.emit('scheduler:started');
  }

  /**
   * Stop the scheduler
   */
  public stop(): void {
    if (!this.running) {
      this.logger.warn('Scheduler not running');
      return;
    }

    this.running = false;
    this.logger.info('Scheduler stopped');

    // Clear all intervals
    for (const [id, interval] of this.intervals.entries()) {
      clearInterval(interval);
      this.intervals.delete(id);
    }

    this.emit('scheduler:stopped');
  }

  /**
   * Get all tasks
   */
  public getTasks(): ScheduledTask[] {
    return Array.from(this.tasks.values());
  }

  /**
   * Get task by ID
   */
  public getTask(id: string): ScheduledTask | undefined {
    return this.tasks.get(id);
  }

  /**
   * Get scheduler status
   */
  public getStatus(): any {
    return {
      running: this.running,
      totalTasks: this.tasks.size,
      enabledTasks: Array.from(this.tasks.values()).filter(t => t.enabled).length,
      disabledTasks: Array.from(this.tasks.values()).filter(t => !t.enabled).length
    };
  }

  private scheduleTask(task: ScheduledTask): void {
    // Clear existing interval if any
    this.unscheduleTask(task.id);

    const interval = this.parseSchedule(task.schedule);
    
    const timer = setInterval(async () => {
      if (task.enabled) {
        try {
          await this.executeTask(task);
        } catch (error) {
          this.logger.error(`Task ${task.id} execution failed:`, error);
        }
      }
    }, interval);

    this.intervals.set(task.id, timer);
  }

  private unscheduleTask(id: string): void {
    const interval = this.intervals.get(id);
    if (interval) {
      clearInterval(interval);
      this.intervals.delete(id);
    }
  }

  private async executeTask(task: ScheduledTask): Promise<AnalysisResults> {
    this.logger.info(`Executing task ${task.id}: ${task.name}`);
    this.emit('task:started', task);

    task.lastRun = new Date();
    task.runCount++;

    try {
      const engine = new AnalysisEngine(task.config);
      const results = await engine.analyze(task.target);

      task.lastResult = results;
      task.nextRun = this.calculateNextRun(task.schedule);

      this.emit('task:completed', { task, results });
      this.logger.info(`Task ${task.id} completed successfully`);

      return results;
    } catch (error: any) {
      this.emit('task:failed', { task, error });
      this.logger.error(`Task ${task.id} failed:`, error);
      throw error;
    }
  }

  private parseSchedule(schedule: string): number {
    // Simple schedule parser
    // Format: "every X [minutes|hours|days]" or "daily at HH:MM"
    
    if (schedule.startsWith('every ')) {
      const parts = schedule.split(' ');
      const value = parseInt(parts[1]);
      const unit = parts[2];

      switch (unit) {
        case 'minute':
        case 'minutes':
          return value * 60 * 1000;
        case 'hour':
        case 'hours':
          return value * 60 * 60 * 1000;
        case 'day':
        case 'days':
          return value * 24 * 60 * 60 * 1000;
        default:
          throw new Error(`Invalid schedule unit: ${unit}`);
      }
    }

    if (schedule.startsWith('daily at ')) {
      // Daily at specific time - default to 24 hours
      return 24 * 60 * 60 * 1000;
    }

    // Default to hourly
    return 60 * 60 * 1000;
  }

  private calculateNextRun(schedule: string): Date {
    const interval = this.parseSchedule(schedule);
    return new Date(Date.now() + interval);
  }
}