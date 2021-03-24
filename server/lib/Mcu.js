const Logger = require('./Logger');
const config = require('../config/config');
const { SocketTimeoutError } = require('./errors');

const logger = new Logger('MCU');

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
		logger.debug('request >>>>> [method:"%s", data:"%o"]', method, data);

		try
		{
			const result = await this._sendRequest(method, data);

			logger.debug('response <<<<< [method:"%s", data:"%o"]', method, result);

			return result;
		}
		catch (error)
		{
			logger.warn('_request(%s) error:%o', method, error);
		}
	}

	async mcuReady(data)
	{
		return await this._request('mcu.ready', data);
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