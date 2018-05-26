
const express = require('express');
const OktaJwtVerifier = require('@okta/jwt-verifier');
const request = require('request');
const crypt=require('./crypto.js');
var cors = require('cors');

const config = require('./.config.json');
const key = process.env.CONF_KEY

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

  var accessToken = match[1];

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
  if (!config.me || !config.me.username || !config.me.password
    || !config.me.assertClaims || !config.me.assertClaims.cid ||
    !config.oidc || !config.oidc.issuer) {
      console.log('Missing config');
      res.json({error: 'Missing config'});
    }
  request.post({
    url: config.oidc.issuer + '/v1/token',
    qs: {
      client_id: config.me.assertClaims.cid
    },
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    form: {
      grant_type:'password',
      username: config.me.username,
      password: crypt.decrypt(config.me.password, key),
      scope: 'openid profile'
    }
  }, function(err,httpResponse,body) {
    if (err || httpResponse.statusCode != 200) {
      console.log("Unable to fetch token", err, httpResponse, body);
      res.json({error:"Unable to fetch token, check server logs"});
    } else {
      var access_token = JSON.parse(body).access_token;
      token = access_token;
      res.json({access_token: access_token});
    }
  });
});

app.get('/userinfo', (req, res) => {
  if (!token) {
    res.status(401);
    return 'Unauthorized';
  }
  request.post({
    url: config.oidc.issuer + '/v1/userinfo',
    qs: {
      client_id: config.me.assertClaims.cid
    },
    headers: {
      'Authorization': 'Bearer ' + token
    }
  }, function(err,httpResponse,body) {
    if (err || httpResponse.statusCode != 200) {
      console.log("Unable to fetch userinfo", err, httpResponse, body);
      res.json("Unable to fetch userinfo, check server logs")
    } else {
      var userinfo = JSON.parse(body);
      res.json(userinfo);
    }
  });
});

/**
 * An example route that requires a valid access token for authentication, it
 * will echo the contents of the access token if the middleware successfully
 * validated the token.
 */
app.get('/secure', authenticationRequired, (req, res) => {
  res.json({message: 'Your email is ' + req.jwt.claims.sub});
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

app.listen(config.me.port, () => {
  console.log(`Server Ready on port ${config.me.port}`);
});
