const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const HTTP_PORT = 8080;
const HTTPS_PORT = 8443;
const BASE_URL = 'http://localhost:8080/auth/realms/comm';

const openIdConfiguration = {
  issuer: BASE_URL,
  authorization_endpoint: `${BASE_URL}/protocol/openid-connect/auth`,
  token_endpoint: `${BASE_URL}/protocol/openid-connect/token`,
  introspection_endpoint: `${BASE_URL}/protocol/openid-connect/token/introspect`,
  userinfo_endpoint: `${BASE_URL}/protocol/openid-connect/userinfo`,
  end_session_endpoint: `${BASE_URL}/protocol/openid-connect/logout`,
  jwks_uri: `${BASE_URL}/protocol/openid-connect/certs`,
  check_session_iframe: `${BASE_URL}/protocol/openid-connect/login-status-iframe.html`,
  revocation_endpoint: `${BASE_URL}/protocol/openid-connect/revoke`,
  device_authorization_endpoint: `${BASE_URL}/protocol/openid-connect/auth/device`,
  grant_types_supported: ['authorization_code', 'implicit', 'refresh_token', 'password', 'client_credentials'],
  response_types_supported: ['code', 'none', 'id_token', 'token', 'id_token token', 'code id_token', 'code token', 'code id_token token'],
  subject_types_supported: ['public', 'pairwise'],
  id_token_signing_alg_values_supported: ['RS256'],
  response_modes_supported: ['query', 'fragment', 'form_post'],
  token_endpoint_auth_methods_supported: ['private_key_jwt', 'client_secret_basic', 'client_secret_post', 'client_secret_jwt'],
  scopes_supported: ['openid', 'profile', 'email', 'phone', 'offline_access', 'address', 'roles', 'web-origins'],
  claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'name', 'given_name', 'family_name', 'preferred_username', 'email', 'email_verified'],
  code_challenge_methods_supported: ['plain', 'S256'],
  backchannel_logout_supported: true,
  backchannel_logout_session_supported: true,
};

const loginPageHtml = fs.readFileSync(path.join(__dirname, 'views', 'loginpage.html'), 'utf8');

const app = express();

// Commercial hem REST hem browser flow'unu destekliyor: her path kendi
// tipine gore (JSON / HTML) yanit veriyor, tanimsiz path'ler icin gercek 404.
app.get('/auth/realms/comm/.well-known/openid-configuration', (req, res) => {
  res.json(openIdConfiguration);
});

app.get('/auth/realms/comm/loginpage', (req, res) => {
  res.type('html').send(loginPageHtml);
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.path });
});

http.createServer(app).listen(HTTP_PORT, () => {
  console.log(`commercial-mock HTTP listening on ${HTTP_PORT}`);
});

https
  .createServer(
    {
      key: fs.readFileSync('/etc/ssl/private/mock.key'),
      cert: fs.readFileSync('/etc/ssl/certs/mock.crt'),
    },
    app
  )
  .listen(HTTPS_PORT, () => {
    console.log(`commercial-mock HTTPS listening on ${HTTPS_PORT}`);
  });
