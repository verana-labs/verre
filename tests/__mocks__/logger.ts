import { BaseLogger, LogLevel } from '@credo-ts/core'
import { ILogObj, Logger } from 'tslog'

// This is a custom logger implementation for testing purposes. It extends the BaseLogger and uses tslog under the hood.
export class TestLogger extends BaseLogger {
  private logger: Logger<ILogObj>

  private tsLogLevelMap = {
    [LogLevel.test]: 'debug',
    [LogLevel.trace]: 'trace',
    [LogLevel.debug]: 'debug',
    [LogLevel.info]: 'info',
    [LogLevel.warn]: 'warn',
    [LogLevel.error]: 'error',
    [LogLevel.fatal]: 'fatal',
  } as const

  public constructor(logLevel: LogLevel, name: string) {
    super(logLevel)

    this.logger = new Logger<ILogObj>({
      name,
      minLevel: this.toTsLogMinLevel(logLevel),
      prettyLogTemplate: '{{yyyy}}-{{mm}}-{{dd}} {{hh}}:{{MM}}:{{ss}}\t{{logLevelName}}\t[{{name}}]\t',
    })
  }

  private toTsLogMinLevel(level: LogLevel): number {
    const map: Record<number, number> = {
      [LogLevel.test]: 2,
      [LogLevel.trace]: 1,
      [LogLevel.debug]: 2,
      [LogLevel.info]: 3,
      [LogLevel.warn]: 4,
      [LogLevel.error]: 5,
      [LogLevel.fatal]: 6,
      [LogLevel.off]: 7,
    }
    return map[level] ?? 3
  }

  private log(level: Exclude<LogLevel, LogLevel.off>, message: string, data?: Record<string, any>): void {
    const tsLogLevel = this.tsLogLevelMap[level]

    if (data) {
      this.logger[tsLogLevel](message, data)
    } else {
      this.logger[tsLogLevel](message)
    }
  }

  public test(message: string, data?: Record<string, any>): void {
    this.log(LogLevel.test, message, data)
  }

  public trace(message: string, data?: Record<string, any>): void {
    this.log(LogLevel.trace, message, data)
  }

  public debug(message: string, data?: Record<string, any>): void {
    this.log(LogLevel.debug, message, data)
  }

  public info(message: string, data?: Record<string, any>): void {
    this.log(LogLevel.info, message, data)
  }

  public warn(message: string, data?: Record<string, any>): void {
    this.log(LogLevel.warn, message, data)
  }

  public error(message: string, data?: Record<string, any>): void {
    this.log(LogLevel.error, message, data)
  }

  public fatal(message: string, data?: Record<string, any>): void {
    this.log(LogLevel.fatal, message, data)
  }
}
