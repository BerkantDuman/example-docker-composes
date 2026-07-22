const express = require('express');
const app = express();
const path = require('path');
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;

app.use(express.json());
app.use(require('./mock-security-server'));

// --- DPoP helpers ---

let _dpopKeyPair = null;

async function getDPoPKeyPair() {
  if (!_dpopKeyPair) {
    _dpopKeyPair = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
  }
  return _dpopKeyPair;
}

function base64urlEncode(input) {
  const buf = Buffer.isBuffer(input)     ? input
            : input instanceof ArrayBuffer ? Buffer.from(input)
            : Buffer.from(input, 'utf8');
  return buf.toString('base64url');
}

async function generateDPoPToken(httpMethod, httpUri, accessToken = null) {
  const keyPair = await getDPoPKeyPair();

  const publicKeyJwk = await subtle.exportKey('jwk', keyPair.publicKey);
  const { d, ...publicJwk } = publicKeyJwk;

  const header  = { typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk };
  const payload = {
    jti: webcrypto.randomUUID(),
    htm: httpMethod.toUpperCase(),
    htu: httpUri,
    iat: Math.floor(Date.now() / 1000)
  };

  if (accessToken) {
    const hashBuffer = await subtle.digest('SHA-256', Buffer.from(accessToken));
    payload.ath = base64urlEncode(hashBuffer);
  }

  const signingInput =
    base64urlEncode(JSON.stringify(header)) + '.' +
    base64urlEncode(JSON.stringify(payload));

  const signatureBuffer = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    Buffer.from(signingInput)
  );

  return `${signingInput}.${base64urlEncode(signatureBuffer)}`;
}

// --- DPoP endpoint ---

app.post('/dpop/generate', async (req, res) => {
  const { httpMethod, httpUri, accessToken } = req.body;

  if (!httpMethod || !httpUri) {
    return res.status(400).json({ error: 'httpMethod ve httpUri zorunludur' });
  }

  try {
    const token = await generateDPoPToken(httpMethod, httpUri, accessToken || null);
    const [rawHeader, rawPayload] = token.split('.');

    res.json({
      dpop: token,
      decoded: {
        header:  JSON.parse(Buffer.from(rawHeader,  'base64url').toString()),
        payload: JSON.parse(Buffer.from(rawPayload, 'base64url').toString())
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Ana sayfa - logout.html'i göster
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'logout.html'));
});

app.get('/callback', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// Keycloak Backchannel Logout endpoint
app.use(express.urlencoded({ extended: true }));
app.post('/backchannel-logout', (req, res) => {
    console.log('Backchannel logout isteği alındı:', req.body);

  const logoutToken = req.body.logout_token;

  if (!logoutToken) {
    console.error('Backchannel logout: logout_token eksik');
    return res.status(400).json({ error: 'logout_token gerekli' });
  }

  // logout_token JWT olarak gelir, decode edip session bilgisi alınabilir
  const payload = JSON.parse(Buffer.from(logoutToken.split('.')[1], 'base64').toString());
  console.log('Backchannel logout alındı:', {
    sub: payload.sub,
    sid: payload.sid,
    iat: payload.iat
  });

  // TODO: Burada ilgili kullanıcının session'ını invalidate et
  // Örn: sessionStore.destroy(payload.sid)

  res.sendStatus(200);
});

// Serve static files from the 'public' directory (AFTER the '/' route)
app.use(express.static(path.join(__dirname, 'public')));

// Define a route for '/test' to serve the index.html file
app.get('/home', (req, res) => {
 setTimeout(() => {
   // req.socket.destroy();

    res.json({
      message: "Delayed response after 3 seconds",
      status: "success"
    });
  }, 300000);


});

// Start the server
app.listen(4000, () => {
  console.log('Server running on http://localhost:4000');
});
