import debug from 'debug';

const APP_NAME = 'edumeet-server';

export default class Logger {
	private _debug: debug.Debugger;

	private _info: debug.Debugger;

	private _warn: debug.Debugger;

	private _error: debug.Debugger;

	constructor(prefix: string) {
		if (prefix) {
			this._debug = this.createLogger(`${APP_NAME}:${prefix}`);
			this._info = this.createLogger(`${APP_NAME}:INFO:${prefix}`);
			this._warn = this.createLogger(`${APP_NAME}:WARN:${prefix}`);
			this._error = this.createLogger(`${APP_NAME}:ERROR:${prefix}`);
		}
		else {
			this._debug = this.createLogger(APP_NAME);
			this._info = this.createLogger(`${APP_NAME}:INFO`);
			this._warn = this.createLogger(`${APP_NAME}:WARN`);
			this._error = this.createLogger(`${APP_NAME}:ERROR`);
		}
	}

	private createLogger(namespace: string): debug.Debugger {
		const logger = debug(namespace);
		logger.log = (...args: any[]) => {
			const now = new Date();
			const options: Intl.DateTimeFormatOptions = {
				year: 'numeric',
				month: '2-digit',
				day: '2-digit',
				hour: '2-digit',
				minute: '2-digit',
				second: '2-digit',
				hour12: false
			};
			const formattedDate = `${now.toLocaleString(undefined, options)}.${now.getMilliseconds().toString().padStart(3, '0')}`;

			// console.log(`[${formattedDate}]`, ...args);
			// 格式化字符串和占位符被分开了，导致占位符不能正确替换。
			// 需要将 formattedDate 和第一个日志参数（即包含占位符的字符串）合并成一个字符串，
			// 然后将其余的参数传递给 console.log
			// 下面slice(1)从 args 数组中获取从索引 1 开始的所有元素，返回一个新数组。
			console.log(`[${formattedDate}]${args[0]}`, ...args.slice(1));
		};
		return logger;
	}

	get debug() {
		return this._debug;
	}

	get info() {
		return this._info;
	}

	get warn() {
		return this._warn;
	}

	get error() {
		return this._error;
	}
}
