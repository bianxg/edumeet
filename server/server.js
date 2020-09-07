#!/usr/bin/env node

process.title = 'multiparty-meeting-server';

const config = require('./config/config');
const fs = require('fs');
const http = require('http');
const spdy = require('spdy');
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const mediasoup = require('mediasoup');
const AwaitQueue = require('awaitqueue');
const Logger = require('./lib/Logger');
const Room = require('./lib/Room');
const Peer = require('./lib/Peer');
const base64 = require('base-64');
const helmet = require('helmet');

const userRoles = require('./userRoles');
const {
	loginHelper,
	logoutHelper
} = require('./httpHelper');
// auth
const passport = require('passport');
const LTIStrategy = require('passport-lti');
const imsLti = require('ims-lti');
const redis = require('redis');
const redisClient = redis.createClient(config.redisOptions);
const { Issuer, Strategy } = require('openid-client');
const expressSession = require('express-session');
const RedisStore = require('connect-redis')(expressSession);
const sharedSession = require('express-socket.io-session');
const interactiveServer = require('./lib/interactiveServer');
const promExporter = require('./lib/promExporter');
const { v4: uuidv4 } = require('uuid');

const LocalStrategy = require('passport-local').Strategy;
const db = require('./db');

/* eslint-disable no-console */
console.log('- process.env.DEBUG:', process.env.DEBUG);
console.log('- config.mediasoup.worker.logLevel:', config.mediasoup.worker.logLevel);
console.log('- config.mediasoup.worker.logTags:', config.mediasoup.worker.logTags);
/* eslint-enable no-console */

const logger = new Logger();

const queue = new AwaitQueue();

let statusLogger = null;

if ('StatusLogger' in config)
	statusLogger = new config.StatusLogger();

// mediasoup Workers.
// @type {Array<mediasoup.Worker>}
const mediasoupWorkers = [];

// Map of Room instances indexed by roomId.
const rooms = new Map();

// Map of Peer instances indexed by peerId.
const peers = new Map();

// TLS server configuration.
const tls =
{
	cert          : fs.readFileSync(config.tls.cert),
	key           : fs.readFileSync(config.tls.key),
	secureOptions : 'tlsv12',
	ciphers       :
	[
		'ECDHE-ECDSA-AES128-GCM-SHA256',
		'ECDHE-RSA-AES128-GCM-SHA256',
		'ECDHE-ECDSA-AES256-GCM-SHA384',
		'ECDHE-RSA-AES256-GCM-SHA384',
		'ECDHE-ECDSA-CHACHA20-POLY1305',
		'ECDHE-RSA-CHACHA20-POLY1305',
		'DHE-RSA-AES128-GCM-SHA256',
		'DHE-RSA-AES256-GCM-SHA384'
	].join(':'),
	honorCipherOrder : true
};

const app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

app.use(helmet.hsts());

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const session = expressSession({
	secret            : config.cookieSecret,
	name              : config.cookieName,
	resave            : true,
	saveUninitialized : true,
	store             : new RedisStore({ client: redisClient }),
	cookie            : {
		secure   : true,
		httpOnly : true,
		maxAge   : 60 * 60 * 1000 // Expire after 1 hour since last request from user
	}
});

if (config.trustProxy)
{
	app.set('trust proxy', config.trustProxy);
}

app.use(session);
/*
passport.serializeUser((user, done) =>
{
	done(null, user);
});

passport.deserializeUser((user, done) =>
{
	done(null, user);
});
*/

let mainListener;
let io;
let oidcClient;
let oidcStrategy;

async function run()
{
	try
	{
		// Open the interactive server.
		await interactiveServer(rooms, peers);

		// start Prometheus exporter
		if (config.prometheus)
		{
			await promExporter(rooms, peers, config.prometheus);
		}

		if (typeof(config.auth) === 'undefined')
		{
			logger.warn('Auth is not configured properly!');
		}
		else
		{
			await setupAuth();
		}

		await setupLocalAuth();

		// Run a mediasoup Worker.
		await runMediasoupWorkers();

		// Run HTTPS server.
		await runHttpsServer();

		// Run WebSocketServer.
		await runWebSocketServer();

		const errorHandler = (err, req, res) =>
		{
			const trackingId = uuidv4();

			res.status(500).send(
				`<h1>Internal Server Error</h1>
				<p>If you report this error, please also report this 
				<i>tracking ID</i> which makes it possible to locate your session
				in the logs which are available to the system administrator: 
				<b>${trackingId}</b></p>`
			);
			logger.error(
				'Express error handler dump with tracking ID: %s, error dump: %o',
				trackingId, err);
		};

		// eslint-disable-next-line no-unused-vars
		app.use(errorHandler);
	}
	catch (error)
	{
		logger.error('run() [error:"%o"]', error);
	}
}

function statusLog()
{
	if (statusLogger)
	{
		statusLogger.log({
			rooms : rooms,
			peers : peers
		});
	}
}

function setupLTI(ltiConfig)
{

	// Add redis nonce store
	ltiConfig.nonceStore = new imsLti.Stores.RedisStore(ltiConfig.consumerKey, redisClient);
	ltiConfig.passReqToCallback= true;

	const ltiStrategy = new LTIStrategy(
		ltiConfig,
		(req, lti, done) =>
		{
			// LTI launch parameters
			if (lti)
			{
				const user = {};

				if (lti.user_id && lti.custom_room)
				{
					user.id = lti.user_id;
					user._userinfo = { 'lti': lti };
				}

				if (lti.custom_room)
				{
					user.room = lti.custom_room;
				}
				else
				{
					user.room = '';
				}
				if (lti.lis_person_name_full)
				{
					user.displayName = lti.lis_person_name_full;
				}

				// Perform local authentication if necessary
				return done(null, user);

			}
			else
			{
				return done('LTI error');
			}

		}
	);

	passport.use('lti', ltiStrategy);
}

function setupOIDC(oidcIssuer)
{

	oidcClient = new oidcIssuer.Client(config.auth.oidc.clientOptions);

	// ... any authorization request parameters go here
	// client_id defaults to client.client_id
	// redirect_uri defaults to client.redirect_uris[0]
	// response type defaults to client.response_types[0], then 'code'
	// scope defaults to 'openid'

	/* eslint-disable camelcase */
	const params = (({
		client_id,
		redirect_uri,
		scope
	}) => ({
		client_id,
		redirect_uri,
		scope
	}))(config.auth.oidc.clientOptions);
	/* eslint-enable camelcase */

	// optional, defaults to false, when true req is passed as a first
	// argument to verify fn
	const passReqToCallback = false;

	// optional, defaults to false, when true the code_challenge_method will be
	// resolved from the issuer configuration, instead of true you may provide
	// any of the supported values directly, i.e. "S256" (recommended) or "plain"
	const usePKCE = false;

	oidcStrategy = new Strategy(
		{ client: oidcClient, params, passReqToCallback, usePKCE },
		(tokenset, userinfo, done) =>
		{
			if (userinfo && tokenset)
			{
				// eslint-disable-next-line camelcase
				userinfo._tokenset_claims = tokenset.claims();
			}

			const user =
			{
				id        : tokenset.claims.sub,
				provider  : tokenset.claims.iss,
				_userinfo : userinfo
			};

			return done(null, user);
		}
	);

	passport.use('oidc', oidcStrategy);
}

async function setupLocalAuth()
{
	// Configure the local strategy for use by Passport.
	//
	// The local strategy require a `verify` function which receives the credentials
	// (`username` and `password`) submitted by the user.  The function must verify
	// that the password is correct and then invoke `cb` with a user object, which
	// will be set at `req.user` in route handlers after authentication.
	passport.use(new LocalStrategy(
		function (username, password, cb) {
			db.users.findByUsername(username, function (err, user) {
				if (err) { return cb(err); }
				if (!user) { return cb(null, false); }
				if (user.password != password) { return cb(null, false); }
				return cb(null, user);
			});
		}));


	// Configure Passport authenticated session persistence.
	//
	// In order to restore authentication state across HTTP requests, Passport needs
	// to serialize users into and deserialize users out of the session.  The
	// typical implementation of this is as simple as supplying the user ID when
	// serializing, and querying the user record by ID from the database when
	// deserializing.
	passport.serializeUser(function (user, cb) {
		cb(null, user.id);
	});

	passport.deserializeUser(function (id, cb) {
		db.users.findById(id, function (err, user) {
			if (err) { return cb(err); }
			cb(null, user);
		});
	});
	
	app.use(passport.initialize());
	app.use(passport.session());

	// Define routes.
	app.get('/auth/login',
		(req, res) => {
			//logger.warn('login  %o',req.query.state);
			//logger.warn('login  %o',req.query);
			//const state = JSON.parse(base64.decode(req.query.state));
			//const { peerId, roomId } = req.query;
			//res.render('login',{peerId:peerId,roomId:roomId});
			res.render('login');
		});

	app.post('/auth/login',
		passport.authenticate('local', { failureRedirect: '/auth/login' }),
		async (req, res,next) => {
			try
			{	
				/*
				const peerId = req.body.peerId;
				const roomId = req.body.roomId;

				req.session.peerId = peerId;
				req.session.roomId = roomId;

				let peer = peers.get(peerId);

				if (!peer) // User has no socket session yet, make temporary
					peer = new Peer({ id: peerId, roomId });

				if (peer.roomId !== roomId) // The peer is mischievous
					throw new Error('peer authenticated with wrong room');

				//logger.info('[login user: "%o"]', req.user);
				//logger.info('-----------------------------');
				//logger.info('[peer: "%o"]', peer);
				//logger.info('-----------------------------');
				

				let _userinfo = {};
				_userinfo.name = req.user.username;
				if (req.user.emails.length > 0)
					_userinfo.email = req.user.emails[0].value;
				_userinfo.picture=null;

				if (typeof config.userMapping === 'function')
				{
					await config.userMapping({
						peer,
						roomId,
						userinfo : _userinfo
					});
				}*/

				//peer.authenticated = true;

				//logger.info('[peer update: "%o"]', peer);
				//logger.info('-----------------------------');

				res.send(loginHelper({
					displayName : req.user.displayName,
					picture     : null
				}));
			}
			catch (error)
			{
				return next(error);
			}
		});
	// logout
	app.get('/auth/logout',
		(req, res) => {
			const { peerId } = req.session;

			const peer = peers.get(peerId);

			if (peer) {
				for (const role of peer.roles) {
					if (role !== userRoles.NORMAL)
						peer.removeRole(role);
				}
			}

			req.logout();
			req.session.destroy(() => res.send(logoutHelper()));
		});
}

async function setupAuth()
{
	// LTI
	if (
		typeof(config.auth.lti) !== 'undefined' &&
		typeof(config.auth.lti.consumerKey) !== 'undefined' &&
		typeof(config.auth.lti.consumerSecret) !== 'undefined'
	) 	setupLTI(config.auth.lti);

	// OIDC
	if (
		typeof(config.auth.oidc) !== 'undefined' &&
		typeof(config.auth.oidc.issuerURL) !== 'undefined' &&
		typeof(config.auth.oidc.clientOptions) !== 'undefined'
	)
	{
		const oidcIssuer = await Issuer.discover(config.auth.oidc.issuerURL);

		// Setup authentication
		setupOIDC(oidcIssuer);

	}

	app.use(passport.initialize());
	app.use(passport.session());

	// loginparams
	app.get('/auth/login', (req, res, next) =>
	{
		passport.authenticate('oidc', {
			state : base64.encode(JSON.stringify({
				peerId : req.query.peerId,
				roomId : req.query.roomId
			}))
		})(req, res, next);
	});

	// lti launch
	app.post('/auth/lti',
		passport.authenticate('lti', { failureRedirect: '/' }),
		(req, res) =>
		{
			res.redirect(`/${req.user.room}`);
		}
	);

	// logout
	app.get('/auth/logout', (req, res) =>
	{
		const { peerId } = req.session;

		const peer = peers.get(peerId);

		if (peer)
		{
			for (const role of peer.roles)
			{
				if (role !== userRoles.NORMAL)
					peer.removeRole(role);
			}
		}

		req.logout();
		req.session.destroy(() => res.send(logoutHelper()));
	});

	// callback
	app.get(
		'/auth/callback',
		passport.authenticate('oidc', { failureRedirect: '/auth/login' }),
		async (req, res, next) =>
		{
			try
			{
				const state = JSON.parse(base64.decode(req.query.state));

				const { peerId, roomId } = state;

				req.session.peerId = peerId;
				req.session.roomId = roomId;

				let peer = peers.get(peerId);

				if (!peer) // User has no socket session yet, make temporary
					peer = new Peer({ id: peerId, roomId });

				if (peer.roomId !== roomId) // The peer is mischievous
					throw new Error('peer authenticated with wrong room');

				if (typeof config.userMapping === 'function')
				{
					await config.userMapping({
						peer,
						roomId,
						userinfo : req.user._userinfo
					});
				}

				peer.authenticated = true;

				res.send(loginHelper({
					displayName : peer.displayName,
					picture     : peer.picture
				}));
			}
			catch (error)
			{
				return next(error);
			}
		}
	);
}

async function runHttpsServer()
{
	app.use(compression());

	app.use('/.well-known/acme-challenge', express.static('public/.well-known/acme-challenge'));

	/*app.all('*', async (req, res, next) =>
	{
		if (req.secure || config.httpOnly)
		{
			let ltiURL;

			try
			{
				ltiURL = new URL(`${req.protocol }://${ req.get('host') }${req.originalUrl}`);
			}
			catch (error)
			{
				logger.error('Error parsing LTI url: %o', error);
			}

			if (
				req.isAuthenticated &&
				req.user &&
				req.user.displayName &&
				!ltiURL.searchParams.get('displayName') &&
				!isPathAlreadyTaken(req.url)
			)
			{

				ltiURL.searchParams.append('displayName', req.user.displayName);

				res.redirect(ltiURL);
			}
			else
				return next();
		}
		else
			res.redirect(`https://${req.hostname}${req.url}`);

	});*/

	// Serve all files in the public folder as static files.
	app.use(express.static('public'));

	app.use((req, res) => res.sendFile(`${__dirname}/public/index.html`));

	if (config.httpOnly === true)
	{
		// http
		mainListener = http.createServer(app);
	}
	else
	{
		// https
		mainListener = spdy.createServer(tls, app);

		// http
		const redirectListener = http.createServer(app);

		if (config.listeningHost)
			redirectListener.listen(config.listeningRedirectPort, config.listeningHost);
		else
			redirectListener.listen(config.listeningRedirectPort);
	}

	// https or http
	if (config.listeningHost)
		mainListener.listen(config.listeningPort, config.listeningHost);
	else
		mainListener.listen(config.listeningPort);
}

function isPathAlreadyTaken(url)
{
	const alreadyTakenPath =
	[
		'/config/',
		'/static/',
		'/images/',
		'/sounds/',
		'/favicon.',
		'/auth/'
	];

	alreadyTakenPath.forEach((path) =>
	{
		if (url.toString().startsWith(path))
			return true;
	});

	return false;
}

/**
 * Create a WebSocketServer to allow WebSocket connections from browsers.
 */
async function runWebSocketServer()
{
	io = require('socket.io')(mainListener);

	io.use(
		sharedSession(session, {
			autoSave : true
		})
	);

	// Handle connections from clients.
	io.on('connection', (socket) =>
	{
		logger.info('on connection, query:"%o"', socket.handshake.query);
		logger.info('on connection, session:"%o"', socket.handshake.session);

		const { roomId, peerId } = socket.handshake.query;

		if (!roomId || !peerId)
		{
			logger.warn('connection request without roomId and/or peerId');

			socket.disconnect(true);

			return;
		}

		logger.info(
			'connection request [roomId:"%s", peerId:"%s"]', roomId, peerId);

		queue.push(async () =>
		{
			const { token } = socket.handshake.session;

			let room;
			if (
				Boolean(socket.handshake.session.passport) &&
				Boolean(socket.handshake.session.passport.user)
			) {
				room = await getOrCreateRoom({ roomId });
			}
			else {
				room = await getOrCreateRoom({ roomId });
				if (!room) {
					logger.error('room "%s" is not exist!', roomId);
					if (socket)
						socket.disconnect(true);
					return;
				}
			}


			let peer = peers.get(peerId);
			let returning = false;

			if (peer && !token)
			{ // Don't allow hijacking sessions
				socket.disconnect(true);

				return;
			}
			else if (token && room.verifyPeer({ id: peerId, token }))
			{ // Returning user, remove if old peer exists
				if (peer)
					peer.close();

				returning = true;
			}

			peer = new Peer({ id: peerId, roomId, socket });

			peers.set(peerId, peer);

			peer.on('close', () =>
			{
				peers.delete(peerId);

				statusLog();
			});

			if (
				Boolean(socket.handshake.session.passport) &&
				Boolean(socket.handshake.session.passport.user)
			)
			{
				logger.info('socket.handshake.session.passport: "%o"',socket.handshake.session.passport);
				logger.info('socket.handshake.session.passport.user: "%o"',socket.handshake.session.passport.user);

				const user = await db.users.getById(socket.handshake.session.passport.user);
				logger.info('user: "%o"',user);
				/*
				const {
					id,
					displayName,
					picture,
					email,
					_userinfo
				} = socket.handshake.session.passport.user;*/

				peer.authId = user.id;
				peer.displayName = user.displayName;
				peer.picture = null;
				peer.email = user.emails[0];
				peer.authenticated = true;

				if (typeof config.userMapping === 'function')
				{
					await config.userMapping({ peer, roomId, userinfo: null });
				}
			}

			room.handlePeer({ peer, returning });

			statusLog();
		})
			.catch((error) =>
			{
				logger.error('room creation or room joining failed [error:"%o"]', error);

				if (socket)
					socket.disconnect(true);

				return;
			});
	});
}

/**
 * Launch as many mediasoup Workers as given in the configuration file.
 */
async function runMediasoupWorkers()
{
	const { numWorkers } = config.mediasoup;

	logger.info('running %d mediasoup Workers...', numWorkers);

	for (let i = 0; i < numWorkers; ++i)
	{
		const worker = await mediasoup.createWorker(
			{
				logLevel   : config.mediasoup.worker.logLevel,
				logTags    : config.mediasoup.worker.logTags,
				rtcMinPort : config.mediasoup.worker.rtcMinPort,
				rtcMaxPort : config.mediasoup.worker.rtcMaxPort
			});

		worker.on('died', () =>
		{
			logger.error(
				'mediasoup Worker died, exiting  in 2 seconds... [pid:%d]', worker.pid);

			setTimeout(() => process.exit(1), 2000);
		});

		mediasoupWorkers.push(worker);
	}
}

/**
 * Get a Room instance (or create one if it does not exist).
 */
async function getOrCreateRoom({ roomId })
{
	let room = rooms.get(roomId);

	// If the Room does not exist create a new one.
	if (!room)
	{
		logger.info('creating a new Room [roomId:"%s"]', roomId);

		// const mediasoupWorker = getMediasoupWorker();

		room = await Room.create({ mediasoupWorkers, roomId });

		rooms.set(roomId, room);

		statusLog();

		room.on('close', () =>
		{
			rooms.delete(roomId);

			statusLog();
		});
	}

	return room;
}

async function getRoom({ roomId })
{
	let room = rooms.get(roomId);
	return room;
}

run();
