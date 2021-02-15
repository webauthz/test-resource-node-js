/* eslint-disable */

const express = require('express');
const helmet = require('helmet');
const { Database } = require('@libertyio/data-collection-memory-js');
const mustacheExpress = require('mustache-express');
const { randomHex } = require('@cryptium/random-node-js');
const { Log } = require('@libertyio/log-node-js');
const { WebauthzTokenMemoryDatabase } = require('@webauthz/sdk-token-data-memory-js');
const { WebauthzToken } = require('@webauthz/sdk-token-core-node-js');
const { WebauthzExpress } = require('@webauthz/sdk-resource-express-node-js');
const bodyParser = require('body-parser');
const cookie = require('cookie');

// http configuration
const { LISTEN_PORT = 29001 } = process.env;
const { ENDPOINT_URL = `http://localhost:${LISTEN_PORT}` } = process.env;

// in-memory database
const database = new Database({ log: new Log({ tag: 'Database', enable: { error: true, warn: true, info: true, trace: true } }) });
const webauthzToken = new WebauthzToken({
    log: new Log({ tag: 'WebauthzToken', enable: { error: true, warn: true, info: true, trace: true } }),
    database: new WebauthzTokenMemoryDatabase(),
});

// middleware to ask browsers not to cache results
function setNoCache(req, res, next) {
  res.set('Pragma', 'no-cache');
  res.set('Cache-Control', 'no-cache, no-store');
  next();
}

// session management
const COOKIE_NAME = 'test_resource';

async function session(req, res, next) {
    let sessionId = null;
    let sessionInfo = {};
    const cookieHeader = req.get('Cookie');
    if (cookieHeader) {
        const cookieMap = cookie.parse(cookieHeader);
        sessionId = cookieMap[COOKIE_NAME];
    }
    if (sessionId) {
        sessionInfo = await database.collection('session').fetchById(sessionId);
    }
    if (!sessionId || !sessionInfo || typeof sessionInfo !== 'object') {
        // create a new session
        sessionId = randomHex(16);
        sessionInfo = { username: null, notAfter: null };
        await database.collection('session').insert(sessionId, sessionInfo);
    }
    // make session content available to routes
    req.session = sessionInfo;
    // set or update the cookie to expire after some time
    const millis = 15 /* minutes */ * 60 /* seconds per minute */ * 1000 /* ms per second */;
    const expiresMillis = Date.now() + millis;
    res.cookie(COOKIE_NAME, sessionId, {
        // ask browser to...
        maxAge: millis, // keep cookie for this length of time (for standards-compliant browsers; the actual header is converted to seconds)
        expires: new Date(expiresMillis), // or keep cookie until this date (for old browsers, should be ignored by browsers that use max-age)
        httpOnly: true, // do not disclose cookie to javascript or extensions unless user grants secure cookie permissions
        secure: process.env.NODE_ENV === 'production', // only send the cookie with https requests
    });
    // listen for end of request processing to store session info
    res.on('finish', async () => {
    // store session data
        await database.collection('session').editById(sessionId, req.session);
    });
    next();
}

function isSessionAuthenticated({ username, notAfter } = {}) {
    return username && typeof notAfter === 'number' && Date.now() <= notAfter;
}

// anyone can login to the demo with a username
// in production a resource server should require authentication (e.g. password), but this is only a demo
async function httpPostLogin(req, res) {
    // login process starts with a non-authenticated session
    req.session.username = null;
    req.session.notAfter = null;
    const { username } = req.body;
    if (typeof username !== 'string' || username.trim().length === 0) {
        console.log('httpPostLogin: non-empty username is required');
        return res.render('main', { error: 'username required to login' });
    }
    
    const seconds = 900; // 60 seconds in 1 minute * 15 minutes
    const expiresMillis = Date.now() + (seconds * 1000);
    req.session.username = username;
    req.session.notAfter = expiresMillis;
    console.log(`httpPostLogin: ${username}`);

    // redirect to main page
    res.status(303);
    res.set('Location', '/');
    res.end();    
}

// logout
async function httpPostLogout(req, res) {
    req.session.username = null;
    req.session.notAfter = null;
    // redirect to main page
    res.status(303);
    res.set('Location', '/');
    res.end();    
}
  
// webauthz authorization

async function httpGetWebauthzDiscoveryJson(req, res) {
  return res.json({
      webauthz_register_uri: `${ENDPOINT_URL}/webauthz/register`,
      webauthz_request_uri: `${ENDPOINT_URL}/webauthz/request`,
      webauthz_exchange_uri: `${ENDPOINT_URL}/webauthz/exchange`,
  });
}

async function httpPostWebauthzRegister(req, res) {
    const { client_name, grant_redirect_uri } = req.body;

    if (typeof client_name !== 'string' || !client_name) {
        res.status(400);
        return res.json({ error: "client_name required" });
    }
    if (typeof grant_redirect_uri !== 'string' || !grant_redirect_uri) {
        res.status(400);
        return res.json({ error: "grant_redirect_uri required" });
    }

    // check that grant_redirect_uri is valid URL
    try {
        const parsedGrantRedirectURI = new URL(grant_redirect_uri);
        console.log(`httpPostWebauthzRegister: grant_redirect_uri origin: ${parsedGrantRedirectURI.origin}`);
    } catch (err) {
        res.status(400);
        return res.json({ error: "grant_redirect_uri must be valid URL" });
    }

    // generate new client id
    const client_id = randomHex(16);
    const registration = { client_name, grant_redirect_uri };
    const isCreated = await database.collection('webauthz_client').insert(client_id, registration);
    if (!isCreated) {
        console.error('httpPostWebauthzRegister: failed to store registration data');
        res.status(500);
        return res.json({ error: "failed to store registration data" });
    }

    // generate new client token; it's the same as an access token but has a special scope to use it with the authorization server for client access
    const access_token = await webauthzToken.generateToken({
        type: 'client',
        client_id,
        realm: 'Webauthz',
        scope: 'webauthz:client',
        path: '/api/webauthz', // it's safe for clients to send their client token to any of our webauthz apis, even though it's only needed for exchange; this also tells the client not to send the token with any unrelated requests that will have a different path under /api
    });

    if (!access_token) {
        console.error('httpPostWebauthzRegister: failed to store client access token');
        res.status(500);
        return res.json({ error: "failed to store client access token" });
    }

    return res.json({
        client_id,
        client_token: access_token,
    });
}

async function httpPostWebauthzRequest(req, res) {
  const { client_state, realm, scope } = req.body;

  if (!req.webauthz.isPermitted()) {
    return req.webauthz.json({ error: 'unauthorized' });
  }

  // input validation

  if (typeof client_state !== 'string' || !client_state) {
      res.status(400);
      return res.render('fault', { fault: 'client_state required' });
  }
  if (typeof realm !== 'string' || !realm) {
      res.status(400);
      return res.render('fault', { fault: 'realm required' });
  }
  if (typeof scope !== 'string' || !scope) {
      res.status(400);
      return res.render('fault', { fault: 'scope required' });
  }

  // get client details 
  const webauthzClientRecord = await database.collection('webauthz_client').fetchById(req.webauthz.client_id);
  if (typeof webauthzClientRecord !== 'object' || webauthzClientRecord === null) {
      res.status(401);
      return res.render('fault', { fault: 'unknown client' });
  }

  const clientURL = new URL(webauthzClientRecord.grant_redirect_uri);

  const webauthzRequestId = randomHex(16);
  const record = {
      client_id: req.webauthz.client_id,
      client_name: webauthzClientRecord.client_name, // to avoid the same lookup again later when user views the prompt
      client_state,
      client_origin: clientURL.origin,
      realm,
      scope,
  };
  const isCreated = await database.collection('webauthz_request').insert(webauthzRequestId, record);
  if (!isCreated) {
      res.status(500);
      return res.render('error', { error: 'failed to store webauthz request' });
  }

  return res.json({
    redirect: `${ENDPOINT_URL}/webauthz/prompt?id=${webauthzRequestId}`,
  });
}

async function httpGetWebauthzPrompt(req, res) {
    const { id } = req.query;

    // input validation
    if (typeof id !== 'string' || !id) {
        console.log('httpGetWebauthzPrompt: bad request: id required');
        res.status(400);
        return res.render('fault', { fault: 'id required' });
    }

    const record = await database.collection('webauthz_request').fetchById(id);
    if (typeof record !== 'object' || record === null) {
        res.status(400);
        return res.render('fault', { fault: 'id unknown' });
    }

    const { client_name, client_origin, realm, scope } = record;

    return res.render('prompt', { id, client_name, client_origin, realm, scope, username: req.session.username });
}

// user interface posts the form here with content-type application/x-www-form-urlencoded

async function httpPostWebauthzPromptSubmit(req, res) {
    const { id, submit } = req.body;

    // only authenticated users may approve or deny a request
    const isAuthenticated = isSessionAuthenticated(req.session);
    if (!isAuthenticated) {
        res.status(401);
        return res.render('main', { error: 'login to manage webauthz requests' });
    }

    // input validation
    if (typeof id !== 'string' || !id) {
        res.status(400);
        return res.render('fault', { fault: "id required" });
    }
    if (typeof submit !== 'string' || !submit) {
        res.status(400);
        return res.render('fault', { fault: "submit required" });
    }

    const record = await database.collection('webauthz_request').fetchById(id);
    if (typeof record !== 'object' || record === null) {
        res.status(400);
        return res.render('fault', { fault: "id unknown" });
    }

    // add the unique identifier of the user to the request
    record.user_id = req.session.username;

    // add the approved or denied status to the request
    switch(submit.toLowerCase()) {
        case 'grant':
            record.status = 'granted';
            break;
        case 'deny':
            record.status = 'denied';
            break;
        default:
            console.log(`httpPostWebauthzPromptSubmit: invalid submit value ${submit}`);
            res.status(400);
            return res.render('fault', { fault: "invalid submit value" });
    }

    let grant_token = null;
    if (record.status === 'granted') {

        // we use client_id as a namespace to minimize the chance of collision; the token space is PER TYPE, PER CLIENT
        grant_token = await webauthzToken.generateToken({ type: 'grant', client_id: record.client_id, requestId: id });      
        if (grant_token === null) {
            res.status(500);
            return res.render('error', { error: "failed to store grant token" });
        }      
    }

    const isEdited = await database.collection('webauthz_request').editById(id, record);

    if (!isEdited) {
        res.status(500);
        return res.render('error', { error: "failed to store request status" });
    }
 
    // generate grant redirect url
    const clientRecord = await database.collection('webauthz_client').fetchById(record.client_id);

    // parse `grant_redirect_uri` to add our own query parameters (it might already have some)
    const parsedGrantRedirectURI = new URL(clientRecord.grant_redirect_uri);
    const grantRedirectParams = new URLSearchParams(parsedGrantRedirectURI.search);
    grantRedirectParams.append('client_id', record.client_id);
    grantRedirectParams.append('client_state', record.client_state);

    if (record.status === 'granted') {
        grantRedirectParams.append('grant_token', grant_token);
    } else {
        grantRedirectParams.append('status', 'denied');
    }

    parsedGrantRedirectURI.search = grantRedirectParams.toString();
    const redirect = parsedGrantRedirectURI.toString();

    res.status(303);
    res.set('Location', redirect);
    res.end();    
}


// this method is accessed by Webauthz applications; response format is JSON in accordance with the specification
async function httpPostWebauthzExchange(req, res) {
    const { grant_token, refresh_token } = req.body;

    if (!req.webauthz.isPermitted()) {
        return req.webauthz.json({ error: 'unauthorized' });
    }

    let requestId;
    if (grant_token) {
        try {
            const grantRecord = await webauthzToken.checkToken(grant_token);
            requestId = grantRecord.requestId;
        } catch (err) {
            this.log.error('httpPostWebauthzExchange: invalid grant token');
            return req.webauthz.json({ error: 'unauthorized' });
        }
    }

    if (refresh_token) {
        try {
            const refreshRecord = await webauthzToken.checkToken(refresh_token);
            requestId = refreshRecord.requestId;
        } catch (err) {
            this.log.error('httpPostWebauthzExchange: invalid grant token');
            return req.webauthz.json({ error: 'unauthorized' });
        }
    }

    // look for the request info
    const requestRecord = await database.collection('webauthz_request').fetchById(requestId);

    // check the client_id matches the request record
    if (req.webauthz.client_id !== requestRecord.client_id) {
        console.error(`httpPostWebauthzExchange: client ${req.webauthz.client_id} != stored ${requestRecord.client_id}`);
        res.status(401);
        return res.json({ error: 'unauthorized' });
    }

    const {
        client_id, // already checked above, is equal to req.webauthz.client_id
        realm,
        scope,
        path,
        not_after,
        user_id,
    } = requestRecord;

    const access_token = await webauthzToken.generateToken({
        type: 'access',
        client_id,
        realm,
        scope,
        path,
        not_after,
        user_id, // this could be added as a scope, or a separate attribute; it will be used later when checking access for SPECIFIC resources within a scope; e.g. scope is "calendar" so application can access THIS USER'S calendar, but not necessarily any OTHER calendars...
    });

    if (!access_token) {
        res.status(500);
        return res.json({ error: 'failed to store access token' });
    }

    return res.json({ access_token });
}

// create resource
async function httpPostCreateResource(req, res) {
    const isAuthenticated = isSessionAuthenticated(req.session);
    if (!isAuthenticated) {
        res.status(401);
        return res.render('main', { error: 'login to create resource' });
    }

    const username = req.session.username;

    const { title, content } = req.body;

    if (typeof title !== 'string' || !title) {
        res.status(400);
        return res.render('main', { error: 'title is required', username, title, content });
    }
    if (typeof content !== 'string' || !content) {
        res.status(400);
        return res.render('main', { error: 'content is required', username, title, content });
    }

    const id = randomHex(8);
    const isCreated = await database.collection('resource').insert(id, { username, title, content });
    if (!isCreated) {
        res.status(500);
        return res.render('main', { error: 'failed to create resource', username, title, content });
    }

    res.status(303);
    res.set('Location', `/resource/${id}`);
    res.end();    
}

// webauthz resource
async function httpGetResource(req, res) {
    const { resourceId } = req.params;

    const accept = req.get('Accept') === 'application/json' ? 'json' : 'html';

    const resource = await database.collection('resource').fetchById(resourceId);
    if (typeof resource !== 'object' || resource === null) {
        res.status(404);
        if (accept === 'json') {
            return res.json({ error: 'not-found' });
        } else {
            return res.render('fault', { fault: 'not found' });
        }
    }

    const isAuthenticated = isSessionAuthenticated(req.session);
    console.log(`httpGetResource isAuthenticated ${isAuthenticated}`);
    if (isAuthenticated && req.session.username === resource.username) {
        if (accept === 'json') {
            return res.json(resource);
        } else {
            return res.render('resource', resource);
        }
    }

    const isPermitted = req.webauthz.isPermitted(); // this checks the scopes required by this resource (see the express route definition for this api) against the access token, but does NOT check this user's access specifically -- we'll do that next if the access token has the required scopes and the resource belongs to a specific user
    console.log(`httpGetResource isPermitted ${isPermitted}`);
    if (isPermitted) {
        // the client is permitted for this resource scope, now we check if it's permitted for this specific resource
        if (resource.username && resource.username !== req.webauthz.user_id) {
            console.log(`httpGetResource: resource.username ${resource.username} != req.webauthz.user_id ${req.webauthz.user_id}`);
            res.status(403); // because more scopes won't fix this
            if (accept === 'json') {
                return res.json({ error: 'forbidden' });
            } else {
                return res.render('fault', { fault: 'forbidden' });
            }
        }
        console.log(`httpGetResource: client ${req.webauthz.client_id} fetching resource ${resourceId}`);
        if (accept === 'json') {
            return res.json(resource);
        } else {
            return res.render('resource', resource);
        }
    }

    if (accept === 'json') {
        return req.webauthz.json();
    } else {
        req.webauthz.header();
        return res.render('fault', { fault: 'login required to access resource' });
    }
}


// user interface routes

async function httpGetMainPage(req, res) {
    let username = null;
    const isAuthenticated = isSessionAuthenticated(req.session);
    if (isAuthenticated) {
        username = req.session.username;
    }
  
    return res.render('main', { username });
}



// configure express framework
const expressApp = express();
expressApp.engine('html', mustacheExpress());
expressApp.set('view engine', 'html');
expressApp.set('views', __dirname + '/views');
expressApp.set('query parser', 'simple');
expressApp.set('x-powered-by', false);
expressApp.use(helmet());
expressApp.use(setNoCache);

// configure webauthz express plugins
const webauthzAuthorizationExpress = new WebauthzExpress({
    log: new Log({ tag: 'WebauthzExpress_Authz', enable: { error: true, warn: true, info: true, trace: true } }),
    plugin: webauthzToken
}); 
const webauthzResourceExpress = new WebauthzExpress({
    log: new Log({ tag: 'WebauthzExpress_Resource', enable: { error: true, warn: true, info: true, trace: true } }),
    plugin: webauthzToken,
    realm: 'Webauthz',
    path: '/resource',
    webauthz_discovery_uri: `${ENDPOINT_URL}/webauthz.json`
});

// resource management requires authenticated session or access token
expressApp.get('/resource/:resourceId', session, webauthzResourceExpress.scope('resource'), httpGetResource);

// webauthz public routes do not require authorization
expressApp.get('/webauthz.json', httpGetWebauthzDiscoveryJson);
expressApp.post('/webauthz/register', bodyParser.json(), httpPostWebauthzRegister);

// webauthz protected routes require a client token
expressApp.post('/webauthz/request', webauthzAuthorizationExpress.scope('webauthz:client'), bodyParser.json(), httpPostWebauthzRequest); // applications start access requests here
expressApp.post('/webauthz/exchange', webauthzAuthorizationExpress.scope('webauthz:client'), bodyParser.json(), httpPostWebauthzExchange); // applications exchange grant tokens for access tokens here

// webauthz user interface routes use a session cookie
expressApp.get('/webauthz/prompt', session, httpGetWebauthzPrompt); // applications redirect here to request access
expressApp.post('/webauthz/prompt', session, bodyParser.urlencoded({ extended: false }), httpPostWebauthzPromptSubmit); // user interface form posts user choice here with content-type application/x-www-form-urlencoded

// configure user interface routes
expressApp.post('/login', session, bodyParser.urlencoded({ extended: false }), httpPostLogin);
expressApp.post('/logout', session, bodyParser.urlencoded({ extended: false }), httpPostLogout);
expressApp.post('/create', session, bodyParser.urlencoded({ extended: false }), httpPostCreateResource);
expressApp.get('/', session, httpGetMainPage);

expressApp.use((err, req, res, next) => {
  if (err) {
      res.status(500);
      if (req.get('Accept') === 'application/json') {
        return res.json({ error: 'server-error' });
      }
      return res.render('error', { error: err.message, stack: err.stack });
  }
  return next(err);
});

// start http server
const server = expressApp.listen(LISTEN_PORT);
console.log('http service started');
console.info(ENDPOINT_URL);

['SIGINT', 'SIGTERM', 'SIGQUIT']
  .forEach(signal => process.on(signal, async () => {
      // shutdown express server
      server.close(() => {
        console.log('Http server closed.');
        process.exit();
      });
  }));

