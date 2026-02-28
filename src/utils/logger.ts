import { Logger, ILogObj } from 'tslog'

import { type IVerreLogger, LogLevel } from '../types.js'

export class VerreLogger implements IVerreLogger {
  private logger: Logger<ILogObj>

  constructor(level: LogLevel = LogLevel.NONE, context?: string) {
    this.logger = new Logger<ILogObj>({
      name: context ?? 'Verre',
      minLevel: this.getLevelValue(level),
      prettyLogTemplate: '{{dateIsoStr}} {{logLevelName}} [{{name}}] ',
    })
  }

  private getLevelValue(level: LogLevel): number {
    const levelMap: Record<LogLevel, number> = {
      none: 7,
      debug: 0,
      info: 3,
      warn: 4,
      error: 5,
    }
    return levelMap[level]
  }

  debug(message: string, meta?: Record<string, unknown>): void {
    this.logger.debug(message, meta)
  }

  info(message: string, meta?: Record<string, unknown>): void {
    this.logger.info(message, meta)
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    this.logger.warn(message, meta)
  }

  error(message: string, error?: Error | unknown): void {
    this.logger.error(message, error)
  }
}
