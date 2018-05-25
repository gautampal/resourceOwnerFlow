
const express = require('express');
const OktaJwtVerifier = require('@okta/jwt-verifier');
const request = require('request');
var cors = require('cors');

const config = require('./.config.json');
const decrypt = process.env.CONF_KEY

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: config.oidc.issuer,
  assertClaims: config.me.assertClaims
});

var token;

/**
 * A simple middleware that asserts valid access tokens and sends 401 responses
 * if the token is not present or fails validation.  If the token is valid its
 * contents are attached to req.jwt
 */
function authenticationRequired(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/Bearer (.+)/);

  if (!match) {
    res.status(401);
    return next('Unauthorized');
  }

  const accessToken = match[1];

  return oktaJwtVerifier.verifyAccessToken(accessToken)
    .then((jwt) => {
      req.jwt = jwt;
      next();
    })
    .catch((err) => {
      res.status(401).send(err.message);
    });
}

const app = express();

/**
 * For local testing only!  Enables CORS for all domains
 */
app.use(cors());

app.get('/', (req, res) => {
  res.json({
    message: 'Hello!  There\'s not much to see here :) Please try /token'
  });
});

app.get('/token', (req, res) => {
  request.post({
    url: config.oidc.issuer + '/v1/token',
    qs: {
      client_id: config.me.assertClaims.cid
    },
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
});

app.get('/userinfo', (req, res) => {
  res.json({
    messages: 'Not implemented'
  });
});

/**
 * An example route that requires a valid access token for authentication, it
 * will echo the contents of the access token if the middleware successfully
 * validated the token.
 */
app.get('/secure', authenticationRequired, (req, res) => {
  res.json(req.jwt);
});

/**
 * Another example route that requires a valid access token for authentication, and
 * print some messages for the user if they are authenticated
 */
app.get('/api/messages', authenticationRequired, (req, res) => {
  res.json({
    messages: [
      {
        date:  new Date(),
        text: 'I am a robot.'
      },
      {
        date:  new Date(new Date().getTime() - 1000 * 60 * 60),
        text: 'Hello, world!'
      }
    ]
  });
});

app.listen(config.resourceServer.port, () => {
  console.log(`Server Ready on port ${config.resourceServer.port}`);
});
