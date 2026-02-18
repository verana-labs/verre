import { Logger, ILogObj } from 'tslog'

export class VerreLogger {
  private logger: Logger<ILogObj>

  constructor(debugMode = false, context?: string) {
    this.logger = new Logger<ILogObj>({
      name: context ?? 'Verre',
      minLevel: debugMode ? 0 : 7,
      prettyLogTemplate: '{{dateIsoStr}} {{logLevelName}} [{{name}}] ',
    })
  }

  child(context: string): VerreLogger {
    const child = new VerreLogger()
    child.logger = this.logger.getSubLogger({ name: context })
    return child
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