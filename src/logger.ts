export function dateFormat(date: Date): string {
  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  const hour = date.getHours().toString().padStart(2, '0');
  const minute = date.getMinutes().toString().padStart(2, '0');
  const second = date.getSeconds().toString().padStart(2, '0');
  const ms = date.getMilliseconds().toString().padStart(3, '0');
  return `${year}-${month}-${day} ${hour}:${minute}:${second},${ms}`;
}


export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export class Logger {
  private static levelEnum = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  }

  private prefix: string
  public silent = false
  public level: LogLevel = 'debug'

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  private log(level: LogLevel, message?: any, ...args: any[]) {
    if (this.silent) return;
    if (Logger.levelEnum[this.level] > Logger.levelEnum[level]) return;

    if (message && typeof message === 'string') {
      console.info(`${dateFormat(new Date())} [${this.prefix}] [${level}] ${message}`, ...args);
    } else {
      console.info(`${dateFormat(new Date())} [${this.prefix}] [${level}]`, message, ...args);
    }
  }

  public debug(message?: any, ...args: any[]) {
    this.log('debug', message, ...args);
  }

  public info(message?: any, ...args: any[]) {
    this.log('info', message, ...args);
  }

  public warn(message?: any, ...args: any[]) {
    this.log('warn', message, ...args);
  }

  public error(message?: any, ...args: any[]) {
    this.log('error', message, ...args);
  }
}
