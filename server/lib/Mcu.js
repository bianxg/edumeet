const Logger = require('./Logger');
const config = require('../config/config');
const { SocketTimeoutError } = require('./errors');

const logger = new Logger('Mcu');

class Mcu
{
	constructor({ socket })
	{
		this._socket = socket;
		this._closed = false;
	}

	get socket()
	{
		return this._socket;
	}

	_timeoutCallback(callback)
	{
		let called = false;

		const interval = setTimeout(
			() =>
			{
				if (called)
					return;
				called = true;
				callback(new Error('Request timed out'));
			},
			10 * 1000
		);

		return (...args) =>
		{
			if (called)
				return;
			called = true;
			clearTimeout(interval);
			callback(...args);
		};
	}

	_sendRequest(method, data)
	{
		return new Promise((resolve, reject) =>
		{
			this._socket.emit(
				'request',
				{ method, data },
				this._timeoutCallback((err, response) =>
				{
					if (err)
					{
						reject(err);
					}
					else
					{
						resolve(response);
					}
				})
			);
		});
	}

	async _request(method, data)
	{
		logger.debug('_request() [method:"%s", data:"%o"]', method, data);

		const {
			requestRetries = 3
		} = config;

		for (let tries = 0; tries < requestRetries; tries++)
		{
			try
			{
				return await this._sendRequest(method, data);
			}
			catch (error)
			{
				if (
					error instanceof SocketTimeoutError &&
					tries < requestRetries
				)
					logger.warn('_request() | timeout, retrying [attempt:"%s"]', tries);
				else
					throw error;
			}
		}
	}

	async webappJoin(data)
	{
		return await this._request('webapp.join', data);
	}

	async webappHangup(data)
	{
		return await this._request('webapp.hangup', data);
	}

	close()
	{
		if (this._closed)
			return;

		this._closed = true;

		if (this._socket)
		{
			this._socket.disconnect(true);
		}
	}
}

module.exports = Mcu;