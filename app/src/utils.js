/**
 * Create a function which will call the callback function
 * after the given amount of milliseconds has passed since
 * the last time the callback function was called.
 */
export const idle = (callback, delay) =>
{
	let handle;

	return () =>
	{
		if (handle)
		{
			clearTimeout(handle);
		}

		handle = setTimeout(callback, delay);
	};
};

/**
 * Error produced when a socket request has a timeout.
 */
export class SocketTimeoutError extends Error
{
	constructor(message)
	{
		super(message);

		this.name = 'SocketTimeoutError';

		if (Error.hasOwnProperty('captureStackTrace')) // Just in V8.
			Error.captureStackTrace(this, SocketTimeoutError);
		else
			this.stack = (new Error(message)).stack;
	}
}

export const formatDuration = (duration) =>
{
	const durationInSeconds = Math.round(duration / 1000);

	const hours = Math.floor(durationInSeconds / 3600);
	const minutes = Math.floor((durationInSeconds - (hours * 3600)) / 60);
	const seconds = durationInSeconds - (minutes * 60) - (hours * 3600);

	const formattedElements = new Array(3);

	formattedElements[0] = seconds < 10 ? '0'.concat(seconds.toString()) : seconds.toString();
	formattedElements[1] = (minutes < 10 ? '0'.concat(minutes.toString()) : minutes.toString()).concat(':');
	formattedElements[2] = hours.toString().concat(':');

	const formattedString = (
		(hours ? formattedElements[2] : '') + formattedElements[1] + formattedElements[0]
	);

	return formattedString;
};