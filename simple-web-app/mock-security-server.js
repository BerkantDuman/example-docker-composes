const express = require('express');
const { randomUUID } = require('crypto');

const router = express.Router();

function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const CHANNELS = ['SMS', 'PUSH', 'EMAIL'];
const VERDICTS = ['AUTHORIZED'];
const REJECT_REASONS = ['USER_REJECTED', 'TIMEOUT', 'CHALLENGE_FAILED', 'EXPIRED'];

router.post('/security-server/submit-for-approval', (req, res) => {
  console.log('[security-server] submit-for-approval isteği alındı, body:', req.body);
  console.log('[security-server] headers:', req.headers);

    const response = {
      authorizationId: randomUUID(),
      challengeDetails: {}
    };

    console.log('[security-server] submit-for-approval cevabı:', response);
    res.status(200).json(response);
});

router.post('/security-server/verify-approval', (req, res) => {
  console.log('[security-server] verify-approval isteği alındı, body:', req.body);
  console.log('[security-server] headers:', req.headers);
  const verdict = randomChoice(VERDICTS);
  const response = {
    status: verdict,
    errorMessage: verdict === 'AUHTORIZED' ? null : randomChoice(REJECT_REASONS),
    remainingAttempts: randomInt(0, 3)
  };

  console.log('[security-server] verify-approval cevabı:', response);
  res.status(200).json(response);
});

router.post('/v1/eligibility/check', (req, res) => {
  console.log('[security-server] /v1/eligibility/check isteği alındı');
  console.log('[security-server] headers:', req.headers);
  console.log('[security-server] body:', req.body);

  res.status(200).json({ isSuccess: true });
});

router.post('/api/logout', (req, res) => {
  console.log('[security-server] /api/logout isteği alındı, body:', req.body);

  res.status(200).json({ success: true });
});

module.exports = router;
