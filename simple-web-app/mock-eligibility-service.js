const express = require('express');

const app = express();
app.use(express.json());

const RESPONSE_DELAY_MS = 2000; // > 1000 → edge timeout'u aşar → Connection reset
                                // < 1000 → edge zamanında cevap alır → normal akış

app.post('/v1/eligibility/check', (req, res) => {
  console.log('[eligibility-service] /v1/eligibility/check isteği alındı');
  console.log('[eligibility-service] headers:', req.headers);
  console.log('[eligibility-service] body:', req.body);
  console.log(`[eligibility-service] ${RESPONSE_DELAY_MS}ms sonra response dönülüyor...`);

  setTimeout(() => {
    console.log('[eligibility-service] response dönülüyor → { isSuccess: true }');
    res.status(200).json({ isSuccess: true });
  }, RESPONSE_DELAY_MS);
});

app.listen(4001, () => {
  console.log('Mock eligibility service running on http://localhost:4001');
});
